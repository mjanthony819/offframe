"""Browser acceptance test: drives the real page in Chrome. Run: python3 tests/ui_test.py [--shots DIR]"""
import sys, os, threading, http.server, socketserver, functools, subprocess, tempfile, json, zipfile
from playwright.sync_api import sync_playwright
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS=sys.argv[sys.argv.index('--shots')+1] if '--shots' in sys.argv else None
if SHOTS: os.makedirs(SHOTS,exist_ok=True)
class Q(http.server.SimpleHTTPRequestHandler):
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
srv=socketserver.TCPServer(('127.0.0.1',0),functools.partial(Q,directory=ROOT))
PORT=srv.server_address[1]
threading.Thread(target=srv.serve_forever,daemon=True).start()
BASE=f'http://127.0.0.1:{PORT}/'
fails=[]
import time
def imgs_ready(pg,t=10):
    s=time.time()
    while time.time()-s<t:
        if all(pg.locator('figure img').nth(i).evaluate('e=>e.complete&&e.naturalWidth>0') for i in range(pg.locator('figure img').count())): return True
        time.sleep(0.1)
    return False
def settled(pg,n,timeout=20):
    t=time.time()
    while time.time()-t<timeout:
        if pg.locator('#queue li').count()==n and pg.locator('.dot.wait').count()==0: return True
        time.sleep(0.1)
    raise TimeoutError('queue did not settle at %d'%n)
def check(cond,msg):
    print(('PASS ' if cond else 'FAIL ')+msg)
    if not cond: fails.append(msg)
with sync_playwright() as p:
    b=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox'])
    ctx=b.new_context(viewport={'width':1360,'height':900},accept_downloads=True)
    pg=ctx.new_page()
    reqs=[];errs=[]
    pg.on('request',lambda r:reqs.append(r.url))
    pg.on('console',lambda m:errs.append(m.text) if m.type=='error' else None)
    pg.on('pageerror',lambda e:errs.append(str(e)))
    pg.goto(BASE); pg.wait_for_selector('#samples')
    check(pg.locator('#empty').is_visible(),'empty state shows first')
    pg.click('#samples'); settled(pg,8)
    names=pg.locator('.qname').all_inner_texts()
    check(names==['trail-photo.jpg','screen-capture.png','trailer.jpg','already-clean.jpg','hostile-comment.jpg','trail-photo.webp','alpha-sticker.webp','animated-clean.webp'],'eight samples queued: %s'%names)
    check(pg.locator('.verdict.hi').is_visible(),'trail-photo shows a high-risk verdict')
    txt=pg.locator('#detail').inner_text()
    check('48.85837, 2.29448' in txt,'GPS coordinates shown for trail-photo')
    check(pg.locator('.checks li.pass').count()==4,'all four checks pass for trail-photo (got %d)'%pg.locator('.checks li.pass').count())
    check(imgs_ready(pg),'before/after previews decode')
    if SHOTS: pg.screenshot(path=f'{SHOTS}/01-trail.png')
    # download clean file and verify independently with exiftool
    with pg.expect_download() as d: pg.click('text=Download clean file')
    out=os.path.join(tempfile.mkdtemp(),d.value.suggested_filename); d.value.save_as(out)
    check(d.value.suggested_filename=='trail-photo.offframe.jpg','download name %s'%d.value.suggested_filename)
    ex=subprocess.run(['exiftool','-GPS:all','-Artist','-SerialNumber','-Make','-Comment','-s3',out],capture_output=True,text=True).stdout.strip()
    check(ex=='','exiftool finds no GPS/artist/serial/make/comment in the downloaded file (got %r)'%ex)
    ori=subprocess.run(['exiftool','-Orientation','-n','-s3',out],capture_output=True,text=True).stdout.strip()
    check(ori=='6','orientation kept in download')
    with pg.expect_download() as d2: pg.click('text=Receipt (JSON)')
    rp=os.path.join(tempfile.mkdtemp(),'r.json'); d2.value.save_as(rp); rec=open(rp).read()
    check('48.85' not in rec and 'SYN-000123' not in rec and '"imageDataIdentical": true' in rec,'receipt has no values and shows the check')
    # other samples
    pg.click('.qitem >> nth=1'); txt=pg.locator('#detail').inner_text()
    check('generator settings or prompt' in txt and 'Last-modified time' in txt,'PNG findings (prompt, tIME) listed')
    check(pg.locator('.checks li.pass').count()==4,'PNG: four checks pass'); check(imgs_ready(pg),'PNG previews decode')
    if SHOTS: pg.screenshot(path=f'{SHOTS}/02-png.png')
    pg.click('.qitem >> nth=2'); txt=pg.locator('#detail').inner_text()
    check('Extra bytes after the end of the image' in txt,'trailer found')
    pg.click('.qitem >> nth=3'); check(pg.locator('.verdict.ok').is_visible(),'clean file gets the all-clear verdict')
    pg.click('.qitem >> nth=4')
    pg.wait_for_selector('#detail .fname')
    check(pg.evaluate('window.__pwned')is None,'hostile metadata did not execute')
    check('<img src=x onerror=' in pg.locator('#detail').inner_text(),'hostile comment is shown as literal text')
    check(pg.locator('#detail img[src="x"]').count()==0,'hostile markup did not become an element')
    if SHOTS: pg.screenshot(path=f'{SHOTS}/03-hostile.png')
    # WebP samples
    pg.click('.qitem >> nth=5'); txt=pg.locator('#detail').inner_text()
    check('lossy WebP' in txt and 'GPS coordinates' in txt,'WebP findings render: %s'%txt[:120])
    check(pg.locator('.checks li.pass').count()==4,'WebP: four checks pass')
    check(imgs_ready(pg),'WebP previews decode')
    if SHOTS: pg.screenshot(path=f'{SHOTS}/03c-webp.png')
    with pg.expect_download() as dc: pg.click('text=Summary card (PNG)')
    cp=os.path.join(tempfile.mkdtemp(),'c.png'); dc.value.save_as(cp)
    check(dc.value.suggested_filename.endswith('.offframe-summary.png') and open(cp,'rb').read(8)==b'\x89PNG\r\n\x1a\n' and os.path.getsize(cp)>20000,'summary card downloads as a real PNG: %s'%dc.value.suggested_filename)
    if SHOTS: import shutil; shutil.copy(cp,f'{SHOTS}/03d-summary-card.png')
    pg.click('.qitem >> nth=6'); check(pg.locator('.checks li.pass').count()==4,'lossless WebP with transparency: four checks pass')
    pg.click('.qitem >> nth=7'); txt=pg.locator('#detail').inner_text()
    check('animated' in txt and pg.locator('.verdict.ok').is_visible(),'animated WebP gets the all-clear verdict')
    # folder picker: 2 images + 1 unsupported file inside
    fd=tempfile.mkdtemp(); import shutil as sh
    sh.copy(ROOT+'/fixtures/trail-photo.webp',fd); sh.copy(ROOT+'/fixtures/screen-capture.png',fd)
    open(fd+'/ignore.txt','w').write('not an image')
    pg.set_input_files('#folderFile',fd); settled(pg,10)
    check('unsupported file' in pg.locator('#status').inner_text(),'folder skip announced: %s'%pg.locator('#status').inner_text())
    # zip
    with pg.expect_download() as d3: pg.click('#zipAll')
    zp=os.path.join(tempfile.mkdtemp(),'z.zip'); d3.value.save_as(zp)
    z=zipfile.ZipFile(zp); check(z.testzip() is None and len([n for n in z.namelist() if n.endswith(('.jpg','.png','.webp'))])==10 and len(z.namelist())==20,'zip valid with 10 images + 10 receipts: %s'%z.namelist()[:4])
    # options: dropping rotation flag reprocesses
    pg.click('#keepOri'); settled(pg,10)
    pg.click('.qitem >> nth=0'); check('rotation flag' in pg.locator('.warn').inner_text(),'rotation warning shown when flag is dropped'); check(pg.locator('.checks li.skip').count()==1,'pixel check skipped with explanation')
    pg.click('.qitem >> nth=5'); pg.wait_for_selector('#detail .fname')
    check(pg.locator('#detail .warn').count()==0,'WebP: no rotation warning (browsers ignore WebP rotation flags)')
    check(pg.locator('.checks li.pass').count()==4,'WebP: pixel check still runs and passes with the flag dropped')
    with pg.expect_download() as d4: pg.click('text=Download clean file')
    o2=os.path.join(tempfile.mkdtemp(),'x.jpg'); d4.value.save_as(o2)
    ori=subprocess.run(['exiftool','-Orientation','-s3',o2],capture_output=True,text=True).stdout.strip()
    check(ori=='','with rotation flag unchecked the download has no orientation (got %r)'%ori)
    # unsupported + corrupt via file chooser
    d=tempfile.mkdtemp(); open(d+'/notes.txt','w').write('hello'); data=open(ROOT+'/fixtures/trail-photo.jpg','rb').read(); open(d+'/cut.jpg','wb').write(data[:2000])
    pg.set_input_files('#file',[d+'/notes.txt',d+'/cut.jpg']); settled(pg,12)
    subs=pg.locator('.qsub').all_inner_texts()
    check(any('Only JPEG, PNG and WebP' in s for s in subs) and any('cut off' in s or 'ends in the middle' in s or 'past the end' in s for s in subs),'unsupported and truncated files refused with readable reasons: %s'%subs[-2:])
    pg.click('.qitem >> nth=10'); check(pg.locator('.card.err').is_visible(),'error card shown')
    # network: only same-origin
    foreign=[r for r in reqs if not r.startswith(BASE) and not r.startswith('blob:') and not r.startswith('data:')]
    check(foreign==[],'no requests left this origin: %s'%foreign)
    check(errs==[],'no console errors: %s'%errs)
    # CSP blocks outbound fetch
    res=pg.evaluate("fetch('https://example.com/x').then(()=>'sent').catch(()=>'blocked')")
    check(res=='blocked','CSP blocks outbound fetch (%s)'%res)
    # mobile
    pg.set_viewport_size({'width':390,'height':844}); pg.click('.qitem >> nth=0'); pg.wait_for_timeout(400)
    if SHOTS: pg.screenshot(path=f'{SHOTS}/04b-mobile-detail.png')
    sw=pg.evaluate('document.documentElement.scrollWidth'); check(sw<=392,'no horizontal overflow at 390px (scrollWidth %d)'%sw)
    if SHOTS: pg.screenshot(path=f'{SHOTS}/04-mobile.png',full_page=False)
    pg.set_viewport_size({'width':320,'height':700}); pg.wait_for_timeout(200)
    sw=pg.evaluate('document.documentElement.scrollWidth'); check(sw<=322,'no horizontal overflow at 320px (scrollWidth %d)'%sw)
    # dark theme
    pg.set_viewport_size({'width':1360,'height':900}); pg.click('#theme'); pg.wait_for_timeout(200)
    if SHOTS: pg.screenshot(path=f'{SHOTS}/05-theme.png')
    # keyboard: drop zone opens chooser on Enter
    with pg.expect_file_chooser() as fc: pg.focus('#drop'); pg.keyboard.press('Enter')
    check(fc.value is not None,'drop zone opens file chooser from keyboard')
    b.close()
print('\nFAILED: %d'%len(fails) if fails else '\nALL UI CHECKS PASSED')
sys.exit(1 if fails else 0)
