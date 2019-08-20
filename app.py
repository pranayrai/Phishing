from flask import Flask, request, render_template
from sklearn import *
from tldextract import extract
import ssl
import socket
import requests
import numpy as np
from sklearn import tree
from bs4 import BeautifulSoup
import bs4
import re
import urllib

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        # Characteristic attribute 6
        def prefix_suffix(url):
            result = ''
            try:
                subDomain, domain, suffix = extract(url)
                # print(domain)
                if ('-' not in domain):
                    result = 'legitimate'
                else:
                    result = 'phishing'
            except Exception as e:
                result = 'phishing'

            if (result == 'phishing'):
                return 1
            else:
                return -1

        # Characteristic attribute 7
        def sub_domain(url):
            result = ''
            try:
                subDomain, domain, suffix = extract(url)
                print(subDomain)
                if ('.' in subDomain):
                    result = 'phishing'
                else:
                    result = 'legitiamte'
            except:
                result = 'phishing'

            if (result == 'phishing'):
                return 1
            else:
                return -1

        # Characteristic attribute 8
        def SSLfinal_State(url):
            result = ''
            try:
                hostname = url.replace("https://", "")
                hostname = url.replace("http://", "")
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
                s.settimeout(10)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issued_to = subject['commonName']
                print(issued_to)
                subDomain, domain, suffix = extract(issued_to)
                print('Retrieved Domain: ' + domain)
                subDomain1, domain1, suffix1 = extract(url)
                print('Original Domain:' + domain1)

                if (domain1 == domain):
                    result = 'legitimate'
                else:
                    result = 'phishing'
            except:
                result = 'phishing'
            if (result == 'phishing'):
                return 1
            else:
                return -1



        # Characteristic attribute 14
        def url_of_anchor(url):
            result = ''
            try:
                r = requests.get(url)
                try:
                    soup = BeautifulSoup(r.text, "html.parser")
                    a = soup.findAll('a')
                    print('Number of a tags: ' + str(len(a)))
                    count = 0
                    for links in a:
                        try:
                            if ('JavaScript' in links['href']):
                                count = count + 1
                        except:
                            continue
                    print('Final Count:' + str(count))
                    if (count == 0):
                        result = 'legitimate'
                except Exception as e:
                    result = 'phishing'
            except:
                result = 'phishing'

            if (result == 'phishing'):
                return 1
            else:
                return -1

        # Characteristic attribute 15
        def link_in_tags(url):
            result = ''
            try:
                r = requests.get(url)
                try:
                    soup = BeautifulSoup(r.text, "html.parser")
                    data = [element.text for element in soup.find_all("script")]
                    total_scripts = len(data)
                    count = 0
                    if (data):
                        for link in data:
                            url = re.findall(
                                'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+] |[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                                link)
                            if (url):
                                count = count + 1
                                print(url)
                            else:
                                continue
                    else:
                        result = 'legitimate'
                    percentage = count / total_scripts
                    print(percentage)
                    if (percentage > 0.3):
                        result = 'phishing'
                    else:
                        result = 'legitimate'
                except Exception as e:
                    result = 'phishing'
            except:
                result = 'phishing'

            if (result == 'phishing'):
                return 1
            else:
                return -1



        # Characteristic attribute 26
        def web_traffic(url):
            result = ''
            try:
                rank = bs4.BeautifulSoup(
                    urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + str(url)).read(),
                    "xml").find("REACH")['RANK']
                if (rank > 100000):
                    result = 'phishing'
                else:
                    result = 'legitimate'
            except:
                result = 'phishing'

            if(result=='phishing'):
                return 1
            else:
                return -1




        # check = [url_having_ip(url), url_length(url), url_short(url), having_at_symbol(url),doubleSlash(url), prefix_suffix(url), sub_domain(url), SSLfinal_State(url),
        #       domain_registration(url), https_token(url)]

        file_path = 'static/docs/optimizedData.csv'
        training_data = np.genfromtxt(file_path, delimiter=',', dtype=np.int32)

        inputs = training_data[:, :-1]
        outputs = training_data[:, -1]

        training_inputs = inputs[:2000]
        training_outputs = outputs[:2000]
        #testing_inputs = inputs[2000:]
        #testing_outputs = outputs[2000:]

        classifier = tree.DecisionTreeClassifier()
        classifier.fit(training_inputs, training_outputs)

        testing_url = np.array([prefix_suffix(url), sub_domain(url), SSLfinal_State(url), url_of_anchor(url), link_in_tags(url), web_traffic(url)])
        #testing_url = np.array([-1, -1, 1, 1, -1, 0])
        testing_url = testing_url.reshape(1, -1)
        print(testing_url)

        predictions = classifier.predict(testing_url)
        if(predictions==1):
            result = 'Phishing'
        else:
            result='Legitimate'
        print(predictions)

        return render_template('index.html', data=result)
    return render_template("index.html", data = "")


if __name__ == '__main__':
    app.run()
