"""Build synthetic fixtures. Every person, serial number, comment and prompt below is invented.
The GPS point is the Eiffel Tower, a public landmark, used only as a stand-in."""
import struct, zlib, subprocess, os, random
from PIL import Image, ImageDraw, ImageFont
F='fixtures'
def scene(w,h,label,seed=1):
    random.seed(seed)
    im=Image.new('RGB',(w,h),(196,224,244))
    d=ImageDraw.Draw(im)
    for y in range(h):
        c=int(244-60*y/h); d.line([(0,y),(w,y)],fill=(c-30,c-4,255-int(40*y/h)))
    d.ellipse([w*0.7,h*0.08,w*0.7+h*0.16,h*0.08+h*0.16],fill=(255,214,102))
    d.polygon([(0,h),(0,h*0.62),(w*0.25,h*0.45),(w*0.5,h*0.62),(w*0.75,h*0.4),(w,h*0.6),(w,h)],fill=(70,110,90))
    d.rectangle([w*0.38,h*0.62,w*0.52,h*0.82],fill=(240,230,210)); d.polygon([(w*0.36,h*0.62),(w*0.45,h*0.5),(w*0.54,h*0.62)],fill=(200,80,70))
    d.rectangle([w*0.43,h*0.7,w*0.47,h*0.82],fill=(90,60,40))
    d.text((12,12),label,fill=(20,30,60))
    d.text((12,h-22),'SYNTHETIC SAMPLE - not a real photo',fill=(255,255,255))
    return im
# 1. phone-style JPEG, stored landscape, EXIF orientation 6, everything populated
im=scene(640,480,'trail-photo.jpg'); im.save(f'{F}/trail-photo.jpg',quality=88,subsampling=2)
th=im.copy(); th.thumbnail((160,120)); th.save('/tmp/th.jpg',quality=70)
subprocess.run(['exiftool','-overwrite_original','-q','-q',
 '-Make=SynthCam','-Model=Sample S1','-Software=SynthCam OS 1.0','-Artist=Sample Person (invented)','-Copyright=(c) Invented Studio',
 '-ImageDescription=Walk near the river, Saturday','-Orientation#=6',
 '-DateTimeOriginal=2026:10:03 07:41:12','-CreateDate=2026:10:03 07:41:12','-ModifyDate=2026:10:03 08:02:00','-OffsetTimeOriginal=+05:30',
 '-SerialNumber=SYN-000123','-LensSerialNumber=LENS-777','-OwnerName=Sample Person (invented)','-LensModel=Sample 24mm f/1.8',
 '-GPSLatitude=48.858370','-GPSLatitudeRef=N','-GPSLongitude=2.294481','-GPSLongitudeRef=E','-GPSAltitude=35','-GPSAltitudeRef=0','-GPSImgDirection=212',
 '-GPSDateStamp=2026:10:03','-GPSTimeStamp=02:11:12',
 '-UserComment=meet at the usual bench','-XPAuthor=Sample Person (invented)','-XPComment=private note (invented)',
 '-XMP-dc:Creator=Sample Person (invented)','-XMP-dc:Rights=(c) Invented Studio','-XMP-photoshop:City=Sample City','-XMP-xmp:CreatorTool=SynthCam OS 1.0',
 '-IPTC:By-line=Sample Person (invented)','-IPTC:City=Sample City','-IPTC:Caption-Abstract=Morning walk','-IPTC:Keywords=river','-IPTC:Credit=Invented Studio',
 '-Comment=exported by SynthCam sample pipeline',
 '-ThumbnailImage<=/tmp/th.jpg', f'{F}/trail-photo.jpg'],check=True)
# 2. JPEG with trailing hidden bytes
scene(480,320,'trailer.jpg',2).save(f'{F}/trailer.jpg',quality=85)
open(f'{F}/trailer.jpg','ab').write(b'SYNTHETIC HIDDEN NOTE: this text sits after the JPEG end marker and no viewer shows it.')
subprocess.run(['exiftool','-overwrite_original','-q','-q','-Make=SynthCam','-Model=Sample S1','-DateTimeOriginal=2026:09:12 18:20:00',f'{F}/trailer.jpg'],check=False)
# exiftool may rewrite the trailer; re-append to be sure
d=open(f'{F}/trailer.jpg','rb').read()
if b'HIDDEN NOTE' not in d: open(f'{F}/trailer.jpg','ab').write(b'SYNTHETIC HIDDEN NOTE: this text sits after the JPEG end marker and no viewer shows it.')
# 3. already clean JPEG
scene(400,300,'already-clean.jpg',3).save(f'{F}/already-clean.jpg',quality=85,optimize=True)
subprocess.run(['exiftool','-all=','-overwrite_original','-q','-q',f'{F}/already-clean.jpg'],check=False)
# 4. PNG screenshot-like image with text chunks, tIME, generator parameters, eXIf with GPS, trailer
def chunk(t,data): 
    c=struct.pack('>I',len(data))+t+data; return c+struct.pack('>I',zlib.crc32(t+data)&0xffffffff)
s=scene(560,360,'screen-capture.png',4); s.save(f'{F}/screen-capture.png',optimize=True)
raw=open(f'{F}/screen-capture.png','rb').read()
chs=[];p=8
while p<len(raw):
    l=struct.unpack('>I',raw[p:p+4])[0]; chs.append((raw[p+4:p+8],raw[p+8:p+8+l])); p+=12+l
out=raw[:8]
for t,dta in chs:
    if t==b'IDAT' and not getattr(chunk,'done',False):
        chunk.done=True
        out+=chunk(b'tEXt',b'Software\x00SynthShot 2.1')
        out+=chunk(b'tEXt',b'Author\x00Sample Person (invented)')
        out+=chunk(b'tEXt',b'Comment\x00captured on the sample laptop named DESK-INVENTED')
        out+=chunk(b'tEXt',b'parameters\x00a tiny house under a blue sky, steps 20, seed 4242 (invented prompt)')
        out+=chunk(b'zTXt',b'Description\x00\x00'+zlib.compress(b'compressed note: draft for the invented project'))
        out+=chunk(b'iTXt',b'XML:com.adobe.xmp\x00\x00\x00\x00\x00'+b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="SynthShot 2.1"><dc:creator><rdf:Seq><rdf:li>Sample Person (invented)</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>')
        out+=chunk(b'tIME',struct.pack('>HBBBBB',2026,10,3,8,2,0))
    out+=chunk(t,dta)
open(f'{F}/screen-capture.png','wb').write(out)
subprocess.run(['exiftool','-overwrite_original','-q','-q','-GPSLatitude=51.500729','-GPSLatitudeRef=N','-GPSLongitude=0.124625','-GPSLongitudeRef=W','-Make=SynthPhone','-Model=Sample P2',f'{F}/screen-capture.png'],check=True)
for f in sorted(os.listdir(F)): print(f, os.path.getsize(f'{F}/{f}'))
# 5. hostile text in metadata: must be shown as text, never run as markup
scene(360,240,'hostile-comment.jpg',5).save(f'{F}/hostile-comment.jpg',quality=85)
subprocess.run(['exiftool','-overwrite_original','-q','-q','-Comment=<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>','-Artist=<b>bold</b> & "quotes"','-Make=SynthCam',f'{F}/hostile-comment.jpg'],check=True)
print('hostile-comment.jpg ok')
# 6. display-critical chunks that must survive: palette + tRNS transparency, gAMA, sRGB, pHYs, plus text that must go
im=scene(200,140,'alpha-palette.png',6).convert('P',palette=Image.ADAPTIVE,colors=32)
im.info['transparency']=0
im.save(f'{F}/alpha-palette.png',transparency=0,dpi=(144,144),optimize=True)
raw=open(f'{F}/alpha-palette.png','rb').read(); out=raw[:8]; p=8; added=False
while p<len(raw):
    l=struct.unpack('>I',raw[p:p+4])[0]; t=raw[p+4:p+8]; d=raw[p+8:p+8+l]
    if t==b'IDAT' and not added:
        added=True
        out+=chunk(b'gAMA',struct.pack('>I',45455))+chunk(b'sRGB',b'\x00')+chunk(b'tEXt',b'Comment\x00invented note that must be removed')
    out+=chunk(t,d); p+=12+l
open(f'{F}/alpha-palette.png','wb').write(out)
# 7. JPEG with an ICC profile (display-relevant, kept by default) plus EXIF that must go
from PIL import ImageCms
icc=ImageCms.ImageCmsProfile(ImageCms.createProfile('sRGB')).tobytes()
scene(320,220,'icc-profile.jpg',7).save(f'{F}/icc-profile.jpg',quality=88,icc_profile=icc)
subprocess.run(['exiftool','-overwrite_original','-q','-q','-Make=SynthCam','-GPSLatitude=40.689','-GPSLatitudeRef=N','-GPSLongitude=74.0445','-GPSLongitudeRef=W',f'{F}/icc-profile.jpg'],check=True)
print('display fixtures ok')

# --- WebP fixtures (v1.1.0) ---
# Note: ExifTool (12.40) cannot WRITE WebP metadata; Pillow 12.x can (exif=/xmp= on save).
src = Image.open(f'{F}/trail-photo.jpg')
exif = src.info.get('exif', b'')
xmp = src.info.get('xmp', b'')
scene(640, 480, 'trail-photo.webp', seed=7).save(f'{F}/trail-photo.webp', 'WEBP', quality=88, exif=exif, xmp=xmp)
rgba = Image.new('RGBA', (320, 240), (0, 0, 0, 0))
d = ImageDraw.Draw(rgba)
d.ellipse([40, 30, 280, 210], fill=(217, 72, 31, 255))
d.text((60, 100), 'alpha webp (synthetic)', fill=(20, 33, 61, 255))
rgba.save(f'{F}/alpha-sticker.webp', 'WEBP', lossless=True, exif=exif)
f1 = scene(240, 180, 'frame 1', seed=11); f2 = scene(240, 180, 'frame 2', seed=12)
f1.save(f'{F}/animated-clean.webp', 'WEBP', save_all=True, append_images=[f2], duration=400, loop=0)
scene(400, 300, 'already-clean.webp', seed=13).save(f'{F}/already-clean.webp', 'WEBP', quality=85)
