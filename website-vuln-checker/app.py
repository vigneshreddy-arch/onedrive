from flask import Flask, render_template, request

from scanner import scan_website

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    report = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        report = scan_website(url)
    return render_template('index.html', report=report, active_page='dashboard')


@app.route('/history')
def history():
    return render_template('history.html', active_page='history')


@app.route('/reports')
def reports():
    return render_template('reports.html', active_page='reports')


@app.route('/settings')
def settings():
    return render_template('settings.html', active_page='settings')


if __name__ == '__main__':
    app.run(debug=True)
