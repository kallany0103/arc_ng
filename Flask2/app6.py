#import Flask in Python
from flask import Flask, render_template
#Create app to hosts the application
app = Flask(__name__)
#Then we need a route that calls a Python function. 
#route maps what we type in the browser (the url) to a Python function.
@app.route('/Home')
@app.route('/')
def Home():
   return render_template('index.html')
   print()
@app.route("/About")
def about():
   return render_template('about.html')
#app.run(host = '0.0.0.0', port =81)
app.run()