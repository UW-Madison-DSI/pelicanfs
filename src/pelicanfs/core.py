"""
Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 
Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 
"""

import cachetools
import fsspec
import fsspec.registry
from fsspec.asyn import AsyncFileSystem, sync
from .dir_header_parser import parse_metalink, get_dirlist_loc
import fsspec.implementations.http as fshttp
import aiohttp
import urllib.parse
import asyncio
import threading
import logging

logger = logging.getLogger("fsspec.pelican")

class PelicanException(RuntimeError):
    """
    Base class for all Pelican-related failures
    """
    pass

class NoAvailableSource(PelicanException):
    """
    No source endpoint is currently available for the requested object
    """
    pass

class PelicanFileSystem(AsyncFileSystem):
    """
    Access a pelican namespace as if it were a file system.

    This exposes a filesystem-like API (ls, cp, open, etc.) on top of pelican

    It works by composing with an http fsspec. Whenever a function call
    is made to the PelicanFileSystem, it will call out to the director to get
    an appropriate url for the given call. This url is then passed on to the 
    http fsspec which will handle the actual logic of the function.

    NOTE: Once a url is passed onto the http fsspec, that url will be the one
    used for all sub calls within the http fsspec.
    """

    protocol = "pelican"

    
    def __init__ (
            self,
            directorUrl,
            asynchronous = False,
            loop = None
    ):
        self._namespace_cache = cachetools.TTLCache(maxsize=50, ttl=15*60)
        self._namespace_lock = threading.Lock()

        # The internal filesystem
        self.httpFileSystem = fshttp.HTTPFileSystem(asynchronous=asynchronous, loop=loop)

        # Ensure the director url ends with a "/"
        if directorUrl[-1] != "/":
            directorUrl = directorUrl + "/"
        self.directorUrl = directorUrl


        super().__init__(self, asynchronous=asynchronous, loop=loop)

        # These are all not implemented in the http fsspec and as such are not implemented in the pelican fsspec
        # They will raise NotImplementedErrors when called
        self._rm_file = self.httpFileSystem._rm_file
        self._cp_file = self.httpFileSystem._cp_file
        self._pipe_file = self.httpFileSystem._pipe_file
        self._mkdir = self.httpFileSystem._mkdir
        self._makedirs = self.httpFileSystem._makedirs
        

        # TODO: These functions are to be implemented. Currently A top level call to glob/du/info will result
        # in a failure
        self._glob = self.httpFileSystem._glob
        self._du = self.httpFileSystem._du
        self._info = self.httpFileSystem._info


    async def get_director_headers(self, fileloc):
        """
        Returns the header response from a GET call to the director
        """
        if fileloc[0] == "/":
            fileloc = fileloc[1:]
        url = self.directorUrl + fileloc
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=False) as resp:
                return resp.headers

    async def get_working_cache(self, fileloc):
        """
        Returns the highest priority cache for the namespace that appears to be owrking
        """
        cacheUrl = self._match_namespace(fileloc)
        if cacheUrl:
            return cacheUrl

        headers = await self.get_director_headers(fileloc)
        metalist, namespace = parse_metalink(headers)
        goodEntry = False
        cache_list = []
        while metalist:
            updatedUrl = metalist[0][0]
            # Timeout response in seconds - the default response is 5 minutes
            timeout = aiohttp.ClientTimeout(total=5)
            session = await self.httpFileSystem.set_session()
            try:
                async with session.head(updatedUrl, timeout=timeout) as resp:
                    pass
                    break
            except (aiohttp.client_exceptions.ClientConnectorError, FileNotFoundError, asyncio.TimeoutError, asyncio.exceptions.TimeoutError):
                pass
            metalist = metalist[1:]
        if not metalist:
            # No working cache was found
            raise NoAvailableSource()
        with self._namespace_lock:
            self._namespace_cache[namespace] = _CacheManager([i[0] for i in metalist])

        return updatedUrl

    def _match_namespace(self, fileloc):
        namespace_info = None
        with self._namespace_lock:
            prefixes = list(self._namespace_cache.keys())
            prefixes.sort(reverse=True)
            for prefix in prefixes:
                if fileloc.startswith(prefix):
                    namespace_info = self._namespace_cache.get(prefix)
                    break
        if not namespace_info:
            return

        return namespace_info.get_url(fileloc)
    
    def _dirlist_dec(func):
        """
        Decorator function which, when given a namespace location, get the url for the dirlist location from the headers
        and uses that url for the given function.

        This is for functions which need to list information in the origin directories such as "find", "isdir", "ls"
        """
        async def wrapper(self, *args, **kwargs):
            path = args[0]
            parsedUrl = urllib.parse.urlparse(path)
            headers = await self.get_director_headers(parsedUrl.path)
            dirlistloc = get_dirlist_loc(headers)
            if dirlistloc == None:
                raise RuntimeError
            listUrl = dirlistloc + "/" + parsedUrl.path
            result = await func(self, listUrl, *args[1:], **kwargs)
            return result
        return wrapper

    @_dirlist_dec
    async def _ls(self, path, detail=True, **kwargs):
        return await self.httpFileSystem._ls(path, detail, **kwargs)

    @_dirlist_dec
    async def _isdir(self, path):
        return await self.httpFileSystem._isdir(path)
    
    @_dirlist_dec
    async def _find(self, path, maxdepth=None, withdirs=False, **kwargs):
        return await self.httpFileSystem._find(path, maxdepth, withdirs, **kwargs)
    
    # Not using a decorator because it requires a yield
    async def _walk(self, path, maxdepth=None, on_error="omit", **kwargs):
        parsedUrl = urllib.parse.urlparse(path)
        headers = await self.get_director_headers(parsedUrl.path)
        dirlistloc = get_dirlist_loc(headers)
        if dirlistloc == "":
            raise RuntimeError
        listUrl = dirlistloc + "/" + path
        async for _ in self.httpFileSystem._walk(listUrl, maxdepth, on_error, **kwargs):
                yield _

    def open(self, path, **kwargs):
        cache_url = sync(self.loop, self.get_working_cache, path)
        return self.httpFileSystem.open(cache_url, **kwargs)

    async def open_async(
        self,
        path,
        **kwargs,
    ):    
        cache_url = await self.get_working_cache(path)
        return self.httpFileSystem.open_async(cache_url, **kwargs)
    


    def _cache_dec(func):
        """
        Decorator function which, when given a namespace location, finds the best working cache that serves the namespace,
        then calls the sub function with that namespace


        Note: This will find the nearest cache even if provided with a valid url. The reason being that if that url was found
        via an "ls" call, then that url points to an origin, not the cache. So it cannot be assumed that a valid url points to
        a cache
        """
        async def wrapper(self, *args, **kwargs):
            path = args[0]
            parsedUrl = urllib.parse.urlparse(path)
            if parsedUrl.scheme == "http":
                cacheUrl = path
            else:
                cacheUrl = await self.get_working_cache(parsedUrl.path)
            result = await func(self, cacheUrl, *args[1:], **kwargs)
            return result
        return wrapper
    
    def _cache_multi_dec(func):
        """
        Decorator function which, when given a list of namespace location, finds the best working cache that serves the namespace,
        then calls the sub function with that namespace


        Note: If a valid url is provided, it will not call the director to get a cache. This does mean that if a url was created/retrieved via
        ls and then used for another function, the url will be an origin url and not a cache url. This should be fixed in the future.
        """
        async def wrapper(self, *args, **kwargs):
            path = args[0]
            if isinstance(path, str):
                parsedUrl = urllib.parse.urlparse(path)
                if parsedUrl.scheme == "http":
                    cacheUrl = path
                else:
                    cacheUrl = await self.get_working_cache(parsedUrl.path)
            else:
                cacheUrl = []
                for p in path:
                    parsedUrl = urllib.parse.urlparse(p)
                    if parsedUrl.scheme == "http":
                        cUrl = p
                    else:
                        cUrl = cacheUrl = await self.get_working_cache(parsedUrl.path)
                    cacheUrl.append(cUrl)
            result = await func(self, cacheUrl, *args[1:], **kwargs)
            return result
        return wrapper

    @_cache_dec
    async def open_async(self, path, mode="rb", size=None, **kwargs):
        return await self.httpFileSystem.open_async(path, mode, size, **kwargs)
    
    @_cache_dec
    async def _cat_file(self, path, start=None, end=None, **kwargs):
        return await self.httpFileSystem._cat_file(path, start, end, **kwargs)

    @_cache_dec
    async def _exists(self, path, **kwargs):
        return await self.httpFileSystem._exists(path, **kwargs)
    
    @_cache_dec
    async def _isfile(self, path, **kwargs):
        return await self.httpFileSystem._isfile(path, **kwargs)
    
    @_cache_dec
    async def _get_file(self, rpath, lpath, **kwargs):
        return await self.httpFileSystem._get_file(rpath, lpath, **kwargs)
    

    @_cache_multi_dec
    async def _cat(self, path, recursive=False, on_error="raise", batch_size=None, **kwargs):
        return await self.httpFileSystem._cat(path, recursive, on_error, batch_size, **kwargs)

    @_cache_multi_dec
    async def _expand_path(self, path, recursive=False, maxdepth=None):
        return await self.httpFileSystem._expand_path(path, recursive, maxdepth)
    
class OSDFFileSystem(PelicanFileSystem):
    """
    A FSSpec AsyncFileSystem representing the OSDF
    """

    protocol = "osdf"

    def __init__(self, **kwargs):
        # TODO: Once the base class takes `pelican://` URLs, switch to
        # `pelican://osg-htc.org`
        super().__init__("https://osdf-director.osg-htc.org", **kwargs)

def PelicanMap(root, pelfs, check=False, create=False):
    loop = asyncio.get_event_loop()
    cache_url = loop.run_until_complete(pelfs.get_working_cache(root))

    return pelfs.get_mapper(cache_url, check=check, create=create)

class _CacheManager(object):
    """
    Manage a list of caches.

    Each entry in the namespace has an associated list of caches that are willing
    to provide services to the client.  As the caches are used, if they timeout
    or otherwise cause errors, they should be skipped for future operations.
    """

    def __init__(self, cache_list):
        """
        Construct a new cache manager from an ordered list of cache URL strings.
        The cache URL is assumed to have the form of:
            scheme://hostname[:port]
        e.g., https://cache.example.com:8443 or http://cache2.example.com

        The list ordering is assumed to be the order of preference; the first cache
        in the list will be used until it's explicitly noted as bad.
        """
        self._lock = threading.Lock()
        self._cache_list = []
        # Work around any bugs where the director may return the same cache twice
        cache_set = set()
        for cache in cache_list:
            parsed_url = urllib.parse.urlparse(cache)
            parsed_url = parsed_url._replace(path="", query="", fragment="")
            cache_str = parsed_url.geturl()
            if cache_str in cache_set:
                continue
            cache_set.add(cache_str)
            self._cache_list.append(parsed_url.geturl())

    def get_url(self, obj_name):
        """
        Given an object name, return the currently-preferred
        """
        with self._lock:
            if not self._cache_list:
                raise NoAvailableSource()

            return urllib.parse.urljoin(self._cache_list[0], obj_name)

    def bad_cache(self, cache_url):
        cache_url_parsed = urllib.parse.urlparse(cache_url)
        cache_url_parsed = cache_url_parsed._replace(path="", query="", fragment="")
        with self._lock:
            self._cache_list.remove(cache_url_parsed.geturl())
