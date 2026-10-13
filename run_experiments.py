# Reproduces the numbers in the SecureWatch paper (Tables ton, syn, ledger).
# Run from the repo /backend folder:  python run_experiments.py
# Needs: pandas, numpy, scikit-learn. Uses fixed seeds (random_state=42).
import pandas as pd, numpy as np, time, json, hashlib, sys
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
res={}
# A: ToN-IoT network
n=pd.read_csv('data/train_test_network.csv')
X=n.select_dtypes(include=[np.number]).drop(columns=['label'],errors='ignore'); y=n['label']
print('features',X.shape[1])
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.25,random_state=42,stratify=y)
t=time.time(); rf=RandomForestClassifier(n_estimators=300,random_state=42,n_jobs=-1).fit(Xtr,ytr); tt=time.time()-t
p=rf.predict(Xte); pr=rf.predict_proba(Xte)[:,1]
res['ton']=dict(n_train=len(Xtr),n_test=len(Xte),acc=accuracy_score(yte,p),prec=precision_score(yte,p),rec=recall_score(yte,p),f1=f1_score(yte,p),auc=roc_auc_score(yte,pr),cm=confusion_matrix(yte,p).tolist(),train_s=tt,nfeat=X.shape[1])
imp=pd.Series(rf.feature_importances_,index=X.columns).sort_values(ascending=False).head(5); res['ton_top']=imp.round(4).to_dict()
# B: synthetic BLE
for name,f,feats in [('syn3k','bluetooth_dataset.csv',None),('syn8k','data/bluetooth_realistic_dataset.csv',None)]:
    d=pd.read_csv(f); X=d.drop(columns='attack'); y=d.attack
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)
    rf=RandomForestClassifier(n_estimators=100,random_state=42).fit(Xtr,ytr); p=rf.predict(Xte)
    r=dict(n=len(d),pos=float(y.mean()),acc=accuracy_score(yte,p),f1=f1_score(yte,p),auc=roc_auc_score(yte,rf.predict_proba(Xte)[:,1]))
    # rule baseline reproducing labels
    if name=='syn3k':
        rule=((d.request_count>10)|(d.manufacturer_known==0)|(d.rssi>-40)).astype(int); r['rule_acc']=float((rule==y).mean())
        # without the rule features (drop all), what's left
        Xr=d[['device_type']]; a,b,c,e=train_test_split(Xr,y,test_size=0.2,random_state=42,stratify=y)
        r['devtype_only_acc']=accuracy_score(e,RandomForestClassifier(100,random_state=42).fit(a,c).predict(b))
        r['majority']=float(max(y.mean(),1-y.mean()))
    else:
        rule=((d.request_count>10)|(d.manufacturer_known==0)|(d.rssi>-40)).astype(int); r['rule_acc']=float((rule==y).mean())
        r['majority']=float(max(y.mean(),1-y.mean()))
    imp=pd.Series(rf.feature_importances_,index=X.columns).sort_values(ascending=False); r['imp']=imp.round(3).to_dict()
    res[name]=r
# C: ledger
sys.path.insert(0,'.')
import io,contextlib
from blockchain import Blockchain
led={}
for N in [100,1000,10000]:
    bc=Blockchain()
    with contextlib.redirect_stdout(io.StringIO()):
        t=time.perf_counter()
        for i in range(N): bc.add_block({'event':'ATTACK','id':i})
        ta=time.perf_counter()-t
    def valid(ch):
        for i in range(1,len(ch)):
            if ch[i].hash!=ch[i].calculate_hash() or ch[i].previous_hash!=ch[i-1].hash: return i
        return -1
    t=time.perf_counter(); v=valid(bc.chain); tv=time.perf_counter()-t
    k=N//2; bc.chain[k].data={'event':'SAFE','id':-1}; pos=valid(bc.chain)
    led[N]=dict(append_ms_per=ta/N*1000,verify_ms=tv*1000,valid_before=(v==-1),tamper_at=k,detected_at=pos)
res['ledger']=led
print(json.dumps(res,indent=1,default=float))
