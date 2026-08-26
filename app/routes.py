from functools import wraps
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for
from .db import acknowledge_alert, add_target, dashboard_data, delete_target, get_user, login_failures, recent_checks, record_event, record_login_attempt, set_target_enabled
from .security import client_key, now, verify_password

bp=Blueprint('main',__name__)

def db_path(): return current_app.config['DB_PATH']

def login_required(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'): return jsonify({'error':'authentication required'}),401
            return redirect(url_for('main.login'))
        return fn(*args,**kwargs)
    return wrapped

def body(name, default=None):
    data=request.get_json(silent=True) or request.form
    return data.get(name,default)

@bp.get('/')
def index():
    if 'user_id' not in session: return redirect(url_for('main.login'))
    targets,events,alerts,total,up=dashboard_data(db_path())
    return render_template('dashboard.html',targets=targets,events=events,alerts=alerts,total=total,up=up)

@bp.route('/login',methods=['GET','POST'])
def login():
    if request.method=='GET': return render_template('login.html')
    path=db_path(); username=(request.form.get('username') or '').strip(); password=request.form.get('password') or ''; ip=request.remote_addr or 'unknown'; key=client_key(ip); current=now()
    if login_failures(path,key,current-300)>=5:
        record_event(path,'login_blocked','warning',ip,'Login temporarily blocked after repeated failures')
        return render_template('login.html',error='Too many failed attempts. Try again later.'),429
    user=get_user(path,username); success=bool(user and verify_password(password,user['password_hash']))
    record_login_attempt(path,key,success,current)
    if not success:
        record_event(path,'login_failure','warning',ip,'Invalid username or password')
        return render_template('login.html',error='Invalid username or password.'),401
    session.clear(); session['user_id']=user['id']; session['username']=user['username']; record_event(path,'login_success','info',ip,'User authenticated')
    return redirect(url_for('main.index'))

@bp.post('/logout')
@login_required
def logout(): record_event(db_path(),'logout','info',request.remote_addr,'User logged out'); session.clear(); return redirect(url_for('main.login'))

@bp.post('/targets')
@login_required
def create_target():
    path=db_path(); name=(body('name') or '').strip(); host=(body('host') or '').strip()
    try: port=int(body('port'))
    except (TypeError,ValueError): return jsonify({'error':'port must be an integer'}),400
    if not name or not host or not 1<=port<=65535 or len(name)>100 or len(host)>255: return jsonify({'error':'invalid target'}),400
    target_id=add_target(path,name,host,port); record_event(path,'target_added','info',request.remote_addr,f'Monitoring target {name}')
    return jsonify({'id':target_id,'message':'target created'}),201

@bp.post('/targets/<int:target_id>/toggle')
@login_required
def toggle(target_id):
    enabled=str(body('enabled','1')).lower() in {'1','true','on'}; set_target_enabled(db_path(),target_id,enabled); return jsonify({'enabled':enabled})

@bp.delete('/targets/<int:target_id>')
@login_required
def remove(target_id):
    path=db_path(); delete_target(path,target_id); record_event(path,'target_removed','info',request.remote_addr,f'Target {target_id} removed'); return jsonify({'message':'deleted'})

@bp.post('/alerts/<int:alert_id>/ack')
@login_required
def ack(alert_id): acknowledge_alert(db_path(),alert_id); return jsonify({'message':'acknowledged'})

@bp.get('/api/overview')
@login_required
def overview():
    ts,ev,al,total,up=dashboard_data(db_path())
    return jsonify({'summary':{'total':total,'up':up,'down':max(total-up,0),'open_alerts':len(al)},'targets':[dict(x) for x in ts],'alerts':[dict(x) for x in al],'events':[dict(x) for x in ev]})

@bp.get('/api/targets/<int:target_id>/history')
@login_required
def history(target_id): return jsonify([dict(x) for x in recent_checks(db_path(),target_id)])
