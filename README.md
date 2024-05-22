# Send2Fing

Una manera, rapida, facil, portable y liviana de mandar archivos por SSH/SCP a las maquinas de la Fing. Esta app, al ejecutar levanta automaticamente un servidor alojado en localhost:5000 y se abrira en tu navegador predeterminado.

## Requerimientos:
```bash
  $ pip install -r requirements.txt
```
## Ejecutando:
  - Hay varias maneras de ejecutarlo, la **recomendada** es la siguiente (Para Linux y Windows):
    ```bash
    cd path/a/la/carpeta
    $ python3 main.py
    ```
  - Para Linux hay dos caminos, uno es abrir el init.sh desde la consola y el otro es abriendo normalmente el init.out (No recomendable, pues el proceso queda abierto en segundo plano) (En revision)
    ```bash
    $ cd path/a/la/carpeta/
    $ ./init.sh
    ```
  - Para Windows, es posible ejecutar el .exe normalmente, tampoco lo recomiendo, quedara en segundo plano y además es posible que popee una ventana de que no se encuentra aplciacion para abrir localhost.

Cualquier aporte es bienvenido.
