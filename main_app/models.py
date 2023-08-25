from sqlalchemy import ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy import Column, Integer, String, DateTime, func
from asyncio import run

engine = create_async_engine(
    'postgresql+asyncpg://postgres:postgres_pwd@postgredb:5432/netology_aiohttp', encoding='utf8')
Session = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base(bind=engine)


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose():
    await engine.dispose()


class User(Base):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_name = Column(String, nullable=False, unique=True, index=True)
    user_email = Column(String, nullable=False, unique=True)
    user_password = Column(String, nullable=False)
    creation_time = Column(DateTime, server_default=func.now())

    advertisement = relationship('Advertisement', cascade='all,delete', back_populates='user')


class Advertisement(Base):

    __tablename__ = 'advertisements'

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    title = Column(String, nullable=False, unique=False)
    description = Column(String, nullable=False, unique=False)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship('User', back_populates='advertisement')


if __name__ == '__main__':
    run(create_tables())

