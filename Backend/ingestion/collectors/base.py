"""
Base Collector interface for GroundedCVE Threat Intelligence feeds.
"""
from abc import ABC, abstractmethod
from typing import List, Optional
from Backend.ingestion.models import StagingEnvelope, SourceType


class BaseCollector(ABC):
    """
    Abstract base class for all threat intelligence data collectors.
    Each collector is responsible for fetching raw data from its respective
    source and packaging each record into a standardized StagingEnvelope.
    """

    def __init__(self, name: str, source_type: SourceType):
        self.name = name
        self.source_type = source_type

    @abstractmethod
    def collect(self, limit: Optional[int] = None) -> List[StagingEnvelope]:
        """
        Fetches upstream raw data and returns a list of standardized StagingEnvelopes.
        
        Args:
            limit: Maximum number of items to retrieve (useful for testing or batch bounds)
            
        Returns:
            List[StagingEnvelope] containing the unmodified raw content and metadata.
        """
        pass
