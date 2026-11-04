#!/usr/bin/env python3
"""Authoring only: preserve approved hardware, repair measured text/state regions.
Production build stays stdlib-only. Pillow is used for mechanical masks/crops.
"""
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter, ImageOps

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "design/landing/equipment"
OUT = ROOT / "website/assets/equipment"
SIZE = (1536, 1024)
REGIONS = {
 "routing-relays": [
 [282,18,985,92],[411,99,754,47],[90,201,311,54],
 [438,184,323,90],[816,207,279,45],[1180,207,275,45],
 [66,537,157,105],[408,402,209,50],[410,560,189,44],
 [1290,337,192,82],[1284,487,197,113],[1286,640,195,104],
 [325,855,379,77],[1021,882,296,49],[438,675,120,38],
 ],
 "gallery-archive": [
 [449,8,725,57],[467,67,782,34],[895,141,218,43],
 [526,212,871,568],[373,234,32,33],
 [635,810,693,45],[542,898,194,65],[876,903,223,55],[1180,896,210,65],
 ],
 "downloads-counter": [
 [345,15,865,68],[549,139,443,36],[1110,201,294,68],
 [250,230,340,75],[250,389,340,84],[250,548,340,94],[250,708,340,95],
 [591,230,108,51],[591,390,108,51],[591,550,108,51],[564,710,137,51],
 [803,264,159,58],[803,424,159,58],[803,584,159,58],[803,744,159,58],
 [314,307,102,46],[314,467,102,46],[314,627,102,46],[314,787,102,46],
 [480,306,220,46],[480,466,220,46],[480,626,220,46],[480,786,220,46],
 [1060,290,388,450],[204,890,710,57],[1050,889,334,60],
 ],}
for y in (205,311,417,523,629,735):
 REGIONS["gallery-archive"].append([196,y+19,180,57])
for cy in (384,538,694):
 REGIONS["routing-relays"] += [[698,cy-28,138,57],[1080,cy-28,79,57],[1034,cy-27,43,48]]
for dy in (0,160,320):
 REGIONS["routing-relays"].append([943,343+dy,51,52])

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def mask(size, regions):
 result = Image.new("L", size)
 for x,y,w,h in regions:
  patch=Image.new("L",(w,h));ImageDraw.Draw(patch).rectangle((3,3,w-4,h-4),fill=255)
  result.paste(patch.filter(ImageFilter.GaussianBlur(.8)),(x,y))
 return result

def main():
 OUT.mkdir(parents=True,exist_ok=True)
 manifest={"tool":"built-in image_gen; deterministic masking/cropping and WebP encoding", "assets":[],"parts":[]}
 masters={}
 for slug,rects in REGIONS.items():
  reference=ART/"concepts"/(slug+".png");clean=ART/(slug+"-clean.png")
  source=Image.open(reference).convert("RGB");repaired=Image.open(clean).convert("RGB")
  assert source.size == repaired.size == SIZE
  master=Image.composite(repaired,source,mask(SIZE,rects))
  masterpath=ART/(slug+"-master.png");master.save(masterpath)
  target=OUT/(slug+".webp");master.save(target,"WEBP",quality=95,method=6)
  masters[slug]=master
  manifest["assets"].append({"name":slug,"size":list(SIZE),"reference":str(reference.relative_to(ROOT)),"referenceSha256":sha(reference),"clean":str(clean.relative_to(ROOT)),"cleanSha256":sha(clean),"repairs":rects,"master":str(masterpath.relative_to(ROOT)),"masterSha256":sha(masterpath),"production":str(target.relative_to(ROOT)),"productionSha256":sha(target),"bytes":target.stat().st_size})
 def part(name,slug,box):
  x,y,w,h=box;image=masters[slug].crop((x,y,x+w,y+h))
  target=OUT/(name+".webp");image.save(target,"WEBP",quality=94,method=6)
  manifest["parts"].append({"name":name,"source":slug,"box":box,"production":str(target.relative_to(ROOT)),"sha256":sha(target),"bytes":target.stat().st_size})
 part("plate-frame","gallery-archive",[87,310,342,96])
 part("relay-body","routing-relays",[825,310,255,136])
 part("device","routing-relays",[46,399,180,292])
 part("client","routing-relays",[345,352,310,405])
 for i,y in enumerate((315,475,635)):
  part("destination-"+str(i),"routing-relays",[1160,y,332,129])
 for i,y in enumerate((205,311,417,523,629,735)):
  part("gallery-key-"+str(i),"gallery-archive",[120,y+13,69,65])
 for i,y in enumerate((207,367,527,687)):
  part("distro-"+str(i),"downloads-counter",[62,y+13,193,155])
 # Nine-slice frames retain the original machined rims for phone compositions.
 for name,slug,box in (("brass-key-frame","gallery-archive",[87,310,342,96]),("steel-key-frame","routing-relays",[438,184,323,90])):
  x,y,w,h=box;image=masters[slug].crop((x,y,x+w,y+h)).convert("RGBA")
  alpha=Image.new("L",image.size,255);ImageDraw.Draw(alpha).rectangle((19,19,w-20,h-20),fill=0);image.putalpha(alpha)
  target=OUT/(name+".webp");image.save(target,"WEBP",quality=95,method=6)
  manifest["parts"].append({"name":name,"source":slug,"box":box,"production":str(target.relative_to(ROOT)),"sha256":sha(target),"bytes":target.stat().st_size})
 part("brass-surface","gallery-archive",[239,335,80,36])
 # Source contact arms are isolated; no substitute lever is generated.
 original=Image.open(ART/"concepts/routing-relays.png").convert("RGBA")
 for i,dy in enumerate((0,160,320)):
  box=(825,310+dy,1080,446+dy);image=original.crop(box);alpha=Image.new("L",image.size)
  points=[(112,57),(149,34),(166,33),(169,48),(127,78),(110,75)]
  ImageDraw.Draw(alpha).polygon(points,fill=255);image.putalpha(alpha)
  target=OUT/("relay-arm-"+str(i)+".webp");image.save(target,"WEBP",quality=95,method=6)
  manifest["parts"].append({"name":"relay-arm-"+str(i),"source":"routing-relays","box":[825,310+dy,255,136],"production":str(target.relative_to(ROOT)),"sha256":sha(target),"bytes":target.stat().st_size})
 # Reflection-symmetric material guarantees matching opposite edges, with no baked light.
 raw=Image.open(ART/"texture-original.png").convert("RGB").resize((128,128),Image.Resampling.LANCZOS)
 tile=Image.new("RGB",(256,256));tile.paste(raw,(0,0));tile.paste(ImageOps.mirror(raw),(128,0));tile.paste(ImageOps.flip(raw),(0,128));tile.paste(ImageOps.flip(ImageOps.mirror(raw)),(128,128))
 target=OUT/"steel-seamless.webp";tile.save(target,"WEBP",lossless=True,method=6)
 manifest["texture"]={"production":str(target.relative_to(ROOT)),"sha256":sha(target),"bytes":target.stat().st_size,"size":[256,256],"edgeMatching":"Opposite decoded RGB edge columns/rows are identical"}
 (ART/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
 layout=json.loads((ROOT/"website/data/equipment-layout.json").read_text())
 css="/* Source coordinates from approved 1536x1024 equipment mockups. */\n@media(min-width:1024px){\n"
 for kind,scene in layout.items():
  for name,(x,y,w,h) in scene["slots"].items():
   css+=f'html[data-enhanced="true"] .equipment-{kind} .{name}'+f'{{left:{x/1536*100:.8f}%;top:{y/1024*100:.8f}%;width:{w/1536*100:.8f}%;height:{h/1024*100:.8f}%;--e-x:{-x/1536*100:.8f}cqw;--e-y:{-y/1536*100:.8f}cqw}}\n'
 css+="}\n"
 (ROOT/"website/assets/equipment-layout.css").write_text(css)
 print(json.dumps({"atlases":{i["name"]:i["bytes"] for i in manifest["assets"]},"partsBytes":sum(i["bytes"] for i in manifest["parts"]),"textureBytes":manifest["texture"]["bytes"]},indent=2))

if __name__ == "__main__":main()
