import json

from bcrypt import hashpw, gensalt, checkpw

from aiohttp import web
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models import Session, User, Advertisement, create_tables, dispose
from schema import PostUser, PatchUser, PostAdv, PatchAdv


async def orm_context(app):
    await create_tables()
    yield
    await dispose()


@web.middleware
async def session_middleware(request: web.Request, handler):
    async with Session() as session:
        request['session'] = session
        response = await handler(request)
        return response


app = web.Application()
app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)


def hash_password(password: str):
    password = password.encode()
    password = hashpw(password, salt=gensalt())
    password = password.decode()
    return password


def validate(json_data, model_class):
    try:
        model_item = model_class(**json_data)
        return model_item.model_dump(exclude_none=True)
    except ValidationError as err:
        raise web.HTTPConflict(
            text=json.dumps({'error': f' WHY!!! {err.errors()}, /// and /// {json_data}'}),
            content_type='application/json'
        )


async def get_user(user_id: int, session: Session):
    user = await session.get(User, user_id)
    if user is None:
        raise web.HTTPConflict(
            text=json.dumps({'error': 'user not found'}),
            content_type='application/json'
        )

    return user


async def get_adv(adv_id: int, session: Session):
    advertisement = await session.get(Advertisement, adv_id)
    if advertisement is None:
        raise web.HTTPConflict(
            text=json.dumps({'error': 'advertisement not found'}),
            content_type='application/json'
        )

    return advertisement


async def authentication(request: web.Request):
    email = request.headers.get('user_email')
    password = request.headers.get('user_password')
    if not email or not password:
        raise web.HTTPConflict(
            text=json.dumps({'error': 'empty email or password'}),
            content_type='application/json'
        )
    async with Session() as session:
        response = await session.execute(select(User).where(getattr(User, 'user_email') == email))
        user = response.scalar()
        user_password_hash = user.user_password
    if not user or not checkpw(password.encode(), user_password_hash.encode()):
        raise web.HTTPConflict(
            text=json.dumps({'error': f'invalid authenticate'}),
            content_type='application/json'
        )
    else:
        return user


class UserView(web.View):

    @property
    def session(self) -> AsyncSession:
        return self.request['session']

    @property
    def user_id(self) -> int:
        return int(self.request.match_info['user_id'])

    async def get(self):
        user = await get_user(self.user_id, self.session)
        return web.json_response({
            'id': user.id,
            'username': user.user_name,
            'email': user.user_email,
            'creation_time': user.creation_time.isoformat()
        })

    async def post(self):
        start_json_data = await self.request.json()
        json_data = validate(start_json_data, PostUser)
        json_data['user_password'] = hash_password(json_data['user_password'])
        try:
            new_user = User(**json_data)
            self.request['session'].add(new_user)
            await self.request['session'].commit()
        except IntegrityError as er:
            raise web.HTTPConflict(
                text=json.dumps({'error': 'user already exists'}),
                content_type='application/json'
            )
        return web.json_response({'id': new_user.id})

    async def patch(self):
        start_json_data = await self.request.json()
        json_data = validate(start_json_data, PatchUser)
        if 'user_password' in json_data:
            json_data['user_password'] = hash_password(json_data['user_password'])

        user = await get_user(self.user_id, self.session)
        for field, value in start_json_data.items():
            setattr(user, field, value)
        try:
            await self.request['session'].commit()
        except IntegrityError as er:
            raise web.HTTPConflict(
                text=json.dumps({'error': 'username is busy'}),
                content_type='application/json'
            )

        return web.json_response({
            'id': user.id,
            'username': user.user_name,
            'creation_time': int(user.creation_time.timestamp())
        })

    async def delete(self):
        user = await get_user(self.user_id, self.session)
        await self.request['session'].delete(user)
        await self.request['session'].commit()
        return web.json_response({
            'status': 'success'
        })


class AdvView(web.View):

    @property
    def session(self) -> AsyncSession:
        return self.request['session']

    @property
    def adv_id(self) -> int:
        return int(self.request.match_info['adv_id'])

    async def get(self):
        adv = await get_adv(self.adv_id, self.session)
        return web.json_response({
            'id': adv.id,
            'title': adv.title,
            'description': adv.description,
            'created_at': adv.created_at.isoformat()
        })

    async def post(self):
        start_json_data = await self.request.json()
        user_auth = await authentication(self.request)
        json_data = validate(start_json_data, PostAdv)
        json_data['owner_id'] = user_auth.id
        new_adv = Advertisement(**json_data)
        self.request['session'].add(new_adv)
        try:
            await self.request['session'].commit()
        except IntegrityError as er:
            raise web.HTTPConflict(
                text=json.dumps({'error': 'advertisement already exists'}),
                content_type='application/json'
            )
        return web.json_response({
            'id': new_adv.id
         })

    async def patch(self):
        start_json_data = await self.request.json()
        user_auth = await authentication(self.request)
        json_data = validate(start_json_data, PatchAdv)
        json_data['owner_id'] = user_auth.id
        adv_id = self.request.match_info['adv_id']
        async with Session() as session:
            result = await session.execute(select(User).join(Advertisement).where(User.id == user_auth.id,
                                                                                  Advertisement.id == int(adv_id)))
        result.scalar()
        if not result:
            raise web.HTTPConflict(
                text=json.dumps({'error': 'you cannot interact with this ad'}),
                content_type='application/json'
            )
        adv = await get_adv(self.adv_id, self.session)
        for field, value in json_data.items():
            setattr(adv, field, value)
        try:
            await self.request['session'].commit()
        except IntegrityError as er:
            raise web.HTTPConflict(
                text=json.dumps({'error': 'advertisement is busy'}),
                content_type='application/json'
            )

        return web.json_response({
            'id': adv.id,
            'title': adv.title,
            'description': adv.description,
            'created_at': int(adv.created_at.timestamp())
        })

    async def delete(self):
        user_auth = await authentication(self.request)
        adv = await get_adv(self.adv_id, self.session)
        await self.request['session'].delete(adv)
        await self.request['session'].commit()
        return web.json_response({
            'status': 'success'
        })


app.add_routes([
    web.post('/user', UserView),
    web.get('/user/{user_id:\d+}', UserView),
    web.patch('/user/{user_id:\d+}', UserView),
    web.delete('/user/{user_id:\d+}', UserView),

    web.post('/advertisement', AdvView),
    web.get('/advertisement/{adv_id:\d+}', AdvView),
    web.patch('/advertisement/{adv_id:\d+}', AdvView),
    web.delete('/advertisement/{adv_id:\d+}', AdvView),
])


if __name__ == '__main__':
    web.run_app(app)
