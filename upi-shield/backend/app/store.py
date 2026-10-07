"""In-memory store. Swap for SQLite/SQLModel when you have time; the API layer won't change."""
from app.schemas import Campaign, Candidate
from app.services.clustering import build_campaigns


class Store:
    def __init__(self) -> None:
        self.candidates: dict[str, Candidate] = {}
        self.campaigns: list[Campaign] = []

    def add(self, c: Candidate) -> None:
        self.candidates[c.id] = c
        self.recluster()

    def recluster(self) -> None:
        for c in self.candidates.values():
            c.campaign_id = None
        self.campaigns = build_campaigns(list(self.candidates.values()))
        for camp in self.campaigns:
            for cid in camp.candidate_ids:
                self.candidates[cid].campaign_id = camp.id


store = Store()
