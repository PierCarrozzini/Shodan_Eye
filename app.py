from flask import Flask, render_template, request
import requests
import shodan
import geocoder 
import subprocess
import psycopg2

######################################################  TEST  #############
# Connect to the database 
conn = psycopg2.connect(database="flask_db", user="postgres", 
                        password="postgres", host="localhost", port="5432") 
  
# create a cursor 
cur = conn.cursor() 
  
# if you already have any table or not id doesnt matter this  
# will create a products table for you. 
cur.execute( 
    '''CREATE TABLE IF NOT EXISTS history (id serial PRIMARY KEY, ip_address inet);''') 
  
# Insert some data into the table 
cur.execute( 
    '''INSERT INTO history (ip_address) VALUES ('192.168.1.1'::INET);''') 
  
# commit the changes 
conn.commit() 
  
# close the cursor and connection 
cur.close() 
conn.close() 

######################################################  FINE TEST  #############

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


#geotag
g = geocoder.ip(public_ip)
# Ottieni l'oggetto Location
location = g.latlng
# Estrai latitudine e longitudine
latitudine = location[0]
longitudine = location[1]
#print(latitudine, longitudine)

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
       
        #print(host)  # Stampa le informazioni sull'host per il debug
        #chiavi = host.keys() 
        #print(chiavi)

       
        vuln = {}

        indexes = len(host['data'])

        for i in range(indexes): 
            lista_vuln = list(host['data'][i].keys())
            for j in (lista_vuln): 
                if j == 'vulns':
                    print(host['data'][i][j].keys())
                    for vul in host['vulns']:
                        reference = []
                        print("VULN_ID: ", vul)
                        print("\n")
                        print("SUMMARY: ", host['data'][i][j][vul]['summary'])
                        print("\n")
                        print("CVSS: ",host['data'][i][j][vul]['cvss'] )
                        print("\n")
                        for ref in range(len(host['data'][i][j][vul]['references'])):
                            #print("REFERENCES: ",host['data'][i][j][vul]['references'][ref])
                            #print("\n")
                            reference.append(host['data'][i][j][vul]['references'][ref])
                        #vuln[vul] = [host['data'][i][j][vul]['summary'],host['data'][i][j][vul]['cvss'],host['data'][i][j][vul]['references'] ]
                        vuln[vul] = [host['data'][i][j][vul]['summary'],host['data'][i][j][vul]['cvss'],reference]
                        #print(reference)
            #print(lista_vuln)
            #for j in lista_vuln: 
            #    print(host['data'][i]['vulns'][j])
                
           
        
        #lista_vuln = list(host['data'][-1]['vulns'].keys())
        """ 
        for vulnerability in host['vulns']:
            #print(vulnerability)
            for j in lista_vuln:
                vuln[vulnerability] = host['data'][-1]['vulns'][j]['summary'] 
        """
               
        
        #print(vuln)  # Stampa ogni vulnerabilità per il debug
        

        """ 
        #cheis = (host['data'][1]['vulns'].keys())
        for i in  host['data']:
            #print(i)
            #print(host['data'][-1]['vulns'].keys())
            lista_vuln = list(host['data'][-1]['vulns'].keys())
            for j in lista_vuln:
                vuln = {'Vuln_ID:' }
                #print("VULN_ID : ", j)
                #print("\n")
                #print("SUMMARY: ",host['data'][-1]['vulns'][j]['summary'])
                return {
                    'ip': host['ip_str'],
                    'port': host['ports'],
                    'country_name' : host['country_name'],
                    'city' : host['city'],
                    'os' : host['os'],
                    'domains' : host['domains'],
                    'vulnerabilities': host['vulns'],
                    'Vuln_ID': j,
                    'summary' : host['data'][-1]['vulns'][j]['summary'],
                    
                 }
        """
        return {
                    'ip': host['ip_str'],
                    'port': host['ports'],
                    'country_name' : host['country_name'],
                    'city' : host['city'],
                    'os' : host['os'],
                    'domains' : host['domains'],
                    'vulnerabilities': host['vulns']
                 }, vuln
        #cheis = host['data']
        #print(cheis)
        
        """ 
        keys = list(host['data'][3]['vulns'].keys())
        print(keys)
        for i in keys: 
            #print(host['data'][3]['vulns'][i])
            print(host['data'][3]['vulns'][i]['summary'])
        

        return {
            'ip': host['ip_str'],
            'port': host['ports'],
            'country_name' : host['country_name'],
            'city' : host['city'],
            'os' : host['os'],
            'domains' : host['domains'],
            'vulnerabilities': host['vulns'],
            'data': host['data'],
        }
        """
    except shodan.APIError as e:
        return {'error': str(e)}


def get_me_info(ip_address):
    try:
        host = api.host(ip_address)
       
        #print(host)  # Stampa le informazioni sull'host per il debug

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
        device_info, vuln = get_device_info(ip_address)
        

        return render_template('results.html', device_info=device_info, context = vuln)

    return render_template('index.html')

@app.route('/results_me', methods=['GET', 'POST'])
def me_info():
    if request.method == 'POST':

        ip_address = public_ip
        print(ip_address)

        # Otteniamo informazioni dettagliate sul dispositivo
        device_info = get_me_info(ip_address)
        #salva l'ip sulla tabella history di postgres
        save_ip(device_info['ip'])
        return render_template('results_me.html', device_info=device_info)

    return render_template('index.html')

def save_ip(ip):
    # create a cursor 
    cur = conn.cursor() 

    # Insert some data into the table 
    cur.execute( '''INSERT INTO history (ip_address) VALUES ({ip}::INET);''') 
  
    # commit the changes 
    conn.commit() 
  
    # close the cursor and connection 
    cur.close() 
    conn.close() 

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
    #return (devices)
    return render_template('results_geo.html', devices=devices)


@app.route('/create_alert', methods=['POST']) 
def create_alert(): 

    command = 'shodan alert enable  new_service,malware,open_database,iot,vulnerable,ssl_expired,industrial_control_system,internet_scanner'

    if request.method == 'POST': 
        name = request.form['name'] 
        net = request.form['net'] 
        expires = int(request.form['expires']) 
 
        try: 
            alert = api.create_alert(name, net, expires=expires) 
            command = f'shodan alert enable {alert['id']} new_service,malware,open_database,iot,vulnerable,ssl_expired,industrial_control_system,internet_scanner'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            print(f"Comando eseguito con successo:\n{result.stdout}")
            return {'message': f"Alert '{alert['id']}' creato con successo."} 
            
        except shodan.APIError as e: 
            return {'error': str(e)} 
     

    if alert: 
        message = f"Alert '{name}' creato con successo.\n" 
        return render_template('create_alert.html', message=message) 
    else: 
        error = str(e) 
        return render_template('create_alert.html', error=error)

    

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)

