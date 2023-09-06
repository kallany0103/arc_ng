from flask import Flask
app1 = Flask(__name__)
@app1.route('/')
def index():
    return 'Hello!'

@app1.route('/drinks')
def get_drinks():
    return {'drinks':'Coca Cola'}
app1.run()