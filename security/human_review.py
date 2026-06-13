import uuid
from datetime import datetime, timezone

class HumanReviewQueue:
    def __init__(self):
        self.reviews = {} # review_id -> review_data

    def create_review(self, tool_call: dict, decision: dict, principal_dict: dict) -> str:
        review_id = str(uuid.uuid4())
        self.reviews[review_id] = {
            "id": review_id,
            "tool": tool_call,
            "policy_reason": decision.get("reason", ""),
            "principal": principal_dict,
            "status": "pending",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        return review_id

    def get_pending_reviews(self) -> list[dict]:
        return [r for r in self.reviews.values() if r["status"] == "pending"]

    def approve(self, review_id: str, reviewer: str = "admin") -> bool:
        if review_id in self.reviews and self.reviews[review_id]["status"] == "pending":
            self.reviews[review_id]["status"] = "approved"
            self.reviews[review_id]["reviewed_by"] = reviewer
            self.reviews[review_id]["reviewed_at"] = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def reject(self, review_id: str, reviewer: str = "admin") -> bool:
        if review_id in self.reviews and self.reviews[review_id]["status"] == "pending":
            self.reviews[review_id]["status"] = "rejected"
            self.reviews[review_id]["reviewed_by"] = reviewer
            self.reviews[review_id]["reviewed_at"] = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def get_status(self, review_id: str) -> str:
        if review_id in self.reviews:
            return self.reviews[review_id]["status"]
        return "not_found"
        
    def get_review(self, review_id: str) -> dict:
        return self.reviews.get(review_id)

human_review_queue = HumanReviewQueue()
