# coding=utf-8
from sqlalchemy import Column, Integer, String, UniqueConstraint, Boolean, DateTime, func
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Threat(Base):
    __tablename__ = 'threat'
    __table_args__ = (
        UniqueConstraint('ip', name='threat_table_ip'),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(15), nullable=False)
    threat_id_info = Column(String(16), nullable=False)
    domain_count = Column(Integer, nullable=False)
    tag_count = Column(Integer, nullable=False)
    itel_count = Column(Integer, nullable=False)
    judge = Column(Integer, nullable=False)
    poc = Column(Boolean, nullable=False)
    ctime = Column(DateTime(timezone=True), server_default=func.now())
    source = Column(Integer, nullable=False)
