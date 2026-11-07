import org.virtualbox_7_0.*;
public final class Vault443Mouse {
 public static void main(String[] args) throws Exception {
  if(args.length!=1 && args.length!=3)throw new IllegalArgumentException("VM-name [zero-based screenshot-x screenshot-y]");
  System.out.println("before manager");
  VirtualBoxManager manager=VirtualBoxManager.createInstance("/usr/lib/virtualbox");
  if(manager==null)throw new IllegalStateException("manager unavailable");
  System.out.println("after manager");
  ISession session=null;
  try {
   IVirtualBox vbox=manager.getVBox();
   System.out.println("after getVBox");
   session=manager.openMachineSession(vbox.findMachine(args[0]));
   System.out.println("after shared console session");
   IMouse mouse=session.getConsole().getMouse();
   System.out.println("absoluteSupported="+mouse.getAbsoluteSupported());
   if(args.length==3) {
    if(!mouse.getAbsoluteSupported())throw new IllegalStateException("Absolute mouse unsupported");
    int x=Integer.parseInt(args[1])+1,y=Integer.parseInt(args[2])+1;
    mouse.putMouseEventAbsolute(x,y,0,0,0);
    mouse.putMouseEventAbsolute(x,y,0,0,1);
    Thread.sleep(60);
    mouse.putMouseEventAbsolute(x,y,0,0,0);
    System.out.println("click+release delivered");
   }
  } finally {
   if(session!=null){session.unlockMachine();System.out.println("unlocked");}
   manager.cleanup();System.out.println("cleanup complete");
  }
 }
}
