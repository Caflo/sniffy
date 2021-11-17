class SnifferTask:
    def __init__(self, id=None, iface=None, active=False, thread_id=None, schedule=None, dynamic=False) -> None:
        self.id = id
        if iface is None:
            raise ValueError("Param 'iface' cannot be None.")
        self.iface = iface
        self.active = active
        self.thread_id = thread_id
        self.schedule = schedule 
        self.dynamic = dynamic  # static or dynamic

    def __lt__(self, other):
        return self.id < other.id

class Schedule:
    def __init__(self, mode, schd_from=None, schd_to=None, interval=None) -> None:
        if mode not in ['range', 'interval']:
            raise ValueError("Parameter 'mode' not valid. You can choose between 'range' and 'interval'")
        self.mode = mode
        if mode == 'range':
            self._from = schd_from
            self._to = schd_to
        elif mode == 'interval':
            self.interval = interval # expressed in minutes
