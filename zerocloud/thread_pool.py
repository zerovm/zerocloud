from eventlet import GreenPool
import uuid
import time


class Zuid(object):

    def __init__(self):
        self._id = '%s' % uuid.uuid4().hex[:3]
        self._counter = 0

    def get(self):
        self._counter += 1
        return '%010x%s%03x' % ((time.time() * 1000), self._id, self._counter)


class PoolInterface(object):

    def can_spawn(self, job_id):
        raise NotImplementedError

    def _spawn(self, function, *args, **kwargs):
        raise NotImplementedError

    def spawn(self, job_id, function, *args, **kwargs):
        if self.can_spawn(job_id):
            return self._spawn(function, *args, **kwargs)

    def force_spawn(self, function, *args, **kwargs):
        return self._spawn(function, *args, **kwargs)


class PriorityPool(PoolInterface):

    def __init__(self, low_watermark=1000, high_watermark=1000):
        self._low_watermark = int(low_watermark)
        self._high_watermark = int(high_watermark)
        self._pool = GreenPool(self._high_watermark)
        self._max_job_id = ''

    def can_spawn(self, job_id):
        if job_id <= self._max_job_id:
            return True
        if self._pool.running() < self._low_watermark:
            self._max_job_id = job_id
            return True
        return False

    def _spawn(self, function, *args, **kwargs):
        return self._pool.spawn(function, *args, **kwargs)


class WaitPool(PoolInterface):
    def __init__(self, pool_size=1000, queue_size=1000):
        self._pool_size = int(pool_size)
        self._queue_size = int(queue_size)
        self._pool = GreenPool(self._pool_size)
        self._max_job_id = ''

    def can_spawn(self, job_id):
        if job_id <= self._max_job_id:
            return True
        if self._pool.free() > 0 or self._pool.waiting() < self._queue_size:
            self._max_job_id = job_id
            return True
        return False

    def _spawn(self, function, *args, **kwargs):
        return self._pool.spawn(function, *args, **kwargs)

