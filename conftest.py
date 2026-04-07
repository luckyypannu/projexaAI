# conftest.py
# Root pytest config + dependency stubs for offline/minimal environments

import sys
import os
import types

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(__file__))

# ── Stub: pymongo ──────────────────────────────────────────────────────────────
if "pymongo" not in sys.modules:
    pymongo_mod = types.ModuleType("pymongo")
    pymongo_mod.ASCENDING = 1

    class _FakeMongoClient:
        def __init__(self, *a, **kw): pass

        def get_default_database(self):
            return self

        def __getitem__(self, name):
            return self

        def create_index(self, *a, **kw): pass

        def update_one(self, *a, **kw): pass

        def bulk_write(self, *a, **kw):
            class Result:
                upserted_count = 0
                modified_count = 0
            return Result()

    class _FakeUpdateOne:
        def __init__(self, *a, **kw): pass

    pymongo_mod.MongoClient = _FakeMongoClient
    pymongo_mod.UpdateOne = _FakeUpdateOne

    collection_mod = types.ModuleType("pymongo.collection")
    collection_mod.Collection = object

    database_mod = types.ModuleType("pymongo.database")
    database_mod.Database = object

    sys.modules["pymongo"] = pymongo_mod
    sys.modules["pymongo.collection"] = collection_mod
    sys.modules["pymongo.database"] = database_mod

# ── Stub: flask_cors ───────────────────────────────────────────────────────────
if "flask_cors" not in sys.modules:
    flask_cors_mod = types.ModuleType("flask_cors")
    flask_cors_mod.CORS = lambda app, **kw: None
    sys.modules["flask_cors"] = flask_cors_mod

# ── Stub: aiohttp ──────────────────────────────────────────────────────────────
if "aiohttp" not in sys.modules:
    aiohttp_mod = types.ModuleType("aiohttp")

    class _FakeTimeout:
        def __init__(self, *a, **kw): pass

    class _FakeResponse:
        def __init__(self):
            self.status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def json(self, **kw):
            return {}

        async def text(self):
            return ""

        def raise_for_status(self):
            if self.status >= 400:
                raise Exception("HTTP Error")

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        # IMPORTANT: NOT async (matches real aiohttp behavior)
        def get(self, *a, **kw):
            return _FakeResponse()

        def post(self, *a, **kw):
            return _FakeResponse()

    aiohttp_mod.ClientSession = _FakeSession
    aiohttp_mod.ClientTimeout = _FakeTimeout

    sys.modules["aiohttp"] = aiohttp_mod

# ── Stub: apscheduler ─────────────────────────────────────────────────────────
if "apscheduler" not in sys.modules:
    for mod_name in [
        "apscheduler",
        "apscheduler.schedulers",
        "apscheduler.schedulers.background",
        "apscheduler.triggers",
        "apscheduler.triggers.interval",
    ]:
        sys.modules[mod_name] = types.ModuleType(mod_name)

    class _FakeScheduler:
        def __init__(self, **kw): pass
        def add_job(self, *a, **kw): pass
        def start(self): pass
        def shutdown(self, *a, **kw): pass

    class _FakeTrigger:
        def __init__(self, **kw): pass

    sys.modules["apscheduler.schedulers.background"].BackgroundScheduler = _FakeScheduler
    sys.modules["apscheduler.triggers.interval"].IntervalTrigger = _FakeTrigger

# ── Stub: nest_asyncio ────────────────────────────────────────────────────────
if "nest_asyncio" not in sys.modules:
    nest_mod = types.ModuleType("nest_asyncio")
    nest_mod.apply = lambda: None
    sys.modules["nest_asyncio"] = nest_mod