from flask import Flask, render_template, request
import requests
import shodan
import geocoder 

url = 'https://api.ipify.org?format=json' #to retrieve public ip_addr 

app = Flask(__name__)
SHODAN_API_KEY = 'hJ4hcLWj7YK3PiIYKqhIaNf0Mw6uGNpQ'  # Replace 'your_api_key_here' with your actual Shodan API key
api = shodan.Shodan(SHODAN_API_KEY)

response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    public_ip = data['ip']
    print(f"Indirizzo IP pubblico: {public_ip}")
   
else:
    print("Richiesta fallita.")

#get the geotag of the device

g = geocoder.ip(public_ip)
# Ottieni l'oggetto Location
location = g.latlng
# Estrai latitudine e longitudine
latitudine = location[0]
longitudine = location[1]
print(latitudine, longitudine)

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

@app.route('/results_me', methods=['GET', 'POST'])
def me_info():
    if request.method == 'POST':

        ip_address = public_ip
        print(ip_address)

        # Otteniamo informazioni dettagliate sul dispositivo
        device_info = get_device_info(ip_address)
        

        return render_template('results_me.html', device_info=device_info)

    return render_template('index.html')

def shodan_search(latitude, longitude):
    try:
        range_km = request.form['range'] 
        # Effettua la ricerca tramite le coordinate geografiche
        results = api.search(f'geo:{latitude},{longitude},{range_km}')
        
        # Estrai informazioni rilevanti
        devices = []
        for result in results['matches']:
            device_info = {
                'ip': result['ip_str'],
                'port': result['port'],
                'organization': result.get('org', 'N/A'),
                'os': result.get('os', 'N/A'),
                'location': result['location'],
                'vulnerabilities': []
            }
            # Recupera informazioni sulle vulnerabilità, se disponibili
            if 'vulns' in result:
                for vuln in result['vulns'].keys():
                    #vuln_info = api.vulnerabilities.get(vuln)
                    device_info['vulnerabilities'].append({
                        'vulnerability': vuln,
                        #'description': vuln_info['description']
                    })

            devices.append(device_info)
        
        return devices
    except shodan.APIError as e:
        return str(e)
    
@app.route('/results_geo', methods=['GET', 'POST'])
def search():
    latitude = latitudine
    longitude = longitudine

    if not (latitude and longitude):
        return ({'error': 'Latitude and longitude parameters are required'}), 400
    
    devices = shodan_search(latitude, longitude)
    return (devices)


@app.route('/create_alert', methods=['POST']) 
def create_alert(): 
    if request.method == 'POST': 
        name = request.form['name'] 
        net = request.form['net'] 
        expires = int(request.form['expires']) 
 
        try: 
            alert = api.create_alert(name, net, expires=expires) 
            return {'message': f"Alert '{name}' creato con successo."} 
        except shodan.APIError as e: 
            return {'error': str(e)} 
     
    if alert: 
        message = f"Alert '{name}' creato con successo. Email di notifica inviata." 
        return render_template('create_alert.html', message=message) 
    else: 
        error = str(e) 
        return render_template('create_alert.html', error=error)


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)


"""

ALLORA SEARCH -> PER SCANSIONE DI TUTTI I DISPOSITIVI 

IN PIU' SI IMPLEMENTA LA RICERCA SUL PROPRIO DEVICE 

E POI IL SISTEMA DI ALERT IN DIRETTA!! 

"""