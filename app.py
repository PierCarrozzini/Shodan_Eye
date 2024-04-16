from flask import Flask, render_template, request
import shodan

app = Flask(__name__)
SHODAN_API_KEY = 'hJ4hcLWj7YK3PiIYKqhIaNf0Mw6uGNpQ'  # Replace 'your_api_key_here' with your actual Shodan API key
api = shodan.Shodan(SHODAN_API_KEY)

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/',  methods=['GET', 'POST'])
def get_device_info(ip_address):
    try:
        host = api.host(ip_address)
        print(host)  # Stampa le informazioni sull'host per il debug

        vulnerabilities = []
        for vulnerability in host['vulns']:
            print(vulnerability)  # Stampa ogni vulnerabilità per il debug
            

        return {
            'ip': host['ip_str'],
            'port': host['ports'],
            'data': host['data'],
            'vulnerabilities': host['vulns']
        }
    except shodan.APIError as e:
        return {'error': str(e)}



# Pagina per visualizzare le informazioni su un dispositivo specifico
@app.route('/results', methods=['GET', 'POST'])
def device_info():
    if request.method == 'POST':
        ip_address = request.form['ip_address']

        # Otteniamo informazioni dettagliate sul dispositivo
        device_info = get_device_info(ip_address)

        return render_template('results.html', device_info=device_info)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)


"""

ALLORA SEARCH -> PER SCANSIONE DI TUTTI I DISPOSITIVI 

IN PIU' SI IMPLEMENTA LA RICERCA SUL PROPRIO DEVICE 

E POI IL SISTEMA DI ALERT IN DIRETTA!! 

"""