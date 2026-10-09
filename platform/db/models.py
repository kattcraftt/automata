from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class FirmwareImage(Base):
    __tablename__ = 'firmware_images'
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    uploaded_at = Column(DateTime)

class AnalysisResult(Base):
    __tablename__ = 'analysis_results'
    id = Column(Integer, primary_key=True)
    firmware_id = Column(Integer, ForeignKey('firmware_images.id'))
    status = Column(String)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    result_id = Column(Integer, ForeignKey('analysis_results.id'))
    description = Column(String)
