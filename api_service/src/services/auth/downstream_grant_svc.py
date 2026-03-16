
class DownstreamGrantService:
    def __init__(self):
        pass

    def issue_downstream_grant(self, req):
        if req is None:
            raise ValueError("downstream grant request is None")