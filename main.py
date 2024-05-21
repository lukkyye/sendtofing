#Este programa fue pensado para facilitar la manera de subir archivos a las maquinas fing.
#
#

from flask import Flask, render_template, request
from paramiko import SSHClient, AutoAddPolicy, ssh_exception
from scp import SCPClient
from os.path import join, dirname, realpath
import webbrowser

#Aqui obtengo la ruta absoluta de /static/uploads/
UPLOADS_PATH = join(dirname(realpath(__file__)), 'static/uploads/')

#Se instancia la clase Flask
app = Flask(__name__)

#Se abre automaticamente la aplicacion local
webbrowser.open("localhost:5000", autoraise=True)

#Se encarga de conectar via SSH para luego enviar por SCP
def send(user: str, password: str, file: str)-> tuple:
    """Conecta por ssh, y envia por scp a las maquinas de la fing

    Args:
        user (str): _Nombre de Usuario de EVA Fing_
        password (str): _Ídem (Contraseña)_
        file (str): _Nombre del archivo a enviar_
    """
    
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(allow_agent=False,hostname=f'lulu.fing.edu.uy', username=f'{user}', password=f'{password}')
    except Exception as error:
        return (False, error)
    scp = SCPClient(ssh.get_transport())
    scp.put(f"{UPLOADS_PATH}"+f'{file}', f'/ens/home01/{user[0]}/{user}/')
    scp.close()
    ssh.close()
    return (True, None)


#Flask backend, obtiene los forms
@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        #Obtiene los campos del <form>
        username = request.form['username']
        password = request.form['password']
        
        #Guarda en /static/uploads el archivo subido
        file = request.files['file']
        file.save(f"{UPLOADS_PATH}"+file.filename)
        
        instance = send(user=username, password=password, file=file.filename)
        if instance[0] == True:
            return render_template('/index.html', ok=True)
        elif instance[0] == False:
            return render_template('/index.html', ok=False, error=instance[1])
    return render_template('/index.html')

#Se abre solamente si se ejecuta este archivo desde aqui mismo xd.
if __name__ == '__main__':
    app.run(
        debug=True
    )
    