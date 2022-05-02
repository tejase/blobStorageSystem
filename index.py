from fastapi import FastAPI
from routes.user import user
from routes.file import file
from fastapi.middleware.cors import CORSMiddleware
from description.description import description
# betaaaaaa

app = FastAPI(
    title="The Murmuring Mountain",
    description=description,
    contact={
        "email": "tejase2531@gmail.com",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(user)
app.include_router(file)
