"""Esta es una plantilla de FastAPI con model User, Auth y DB """
from fastapi import FastAPI, Request, status

# Para enviar respuestas HTML
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Imports Locales
from utils.database import Base, engine
from routers import users
from utils.init_db import init_approved_users

# Instancia la ceación de la base y sus tablas sino existen
Base.metadata.create_all(bind=engine)
# Inicializo la DB
init_approved_users()
# Instancia la aplicación de FastAPI
app = FastAPI(
    title="FastAPI Template",
    description="Este es una plantilla de app en FastAPI",
    version="1.0.0",
)

# Montar archivos estáticos (CSS/JS/Imagenes)
app.mount("/static", StaticFiles(directory="static"), name="static")
# Monta los archivos de imagenes de usuario
app.mount("/media", StaticFiles(directory="media"), name="media")
# Configurar motor de plantillas
templates = Jinja2Templates(directory="templates")
# Enrutadores
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])


# Muestra la pagina principal del sitio
@app.get(
    "/",
    name="inicio",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def inicio(request: Request):
    """Renderiza la página inicial"""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"Mensaje": "Solo el primer mensaje"},
    )
