import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from phantom.core import PhantomScanner,DecoyGenerator

class TestPhantom(unittest.TestCase):
    def test_scan_info(self):
        s=PhantomScanner()
        r=s.get_scan_info("syn")
        self.assertEqual(r["flags"],0x02)
    def test_header(self):
        s=PhantomScanner()
        h=s.build_tcp_header(12345,80,0x02)
        self.assertEqual(h["dst_port"],80)
    def test_plan(self):
        s=PhantomScanner()
        p=s.plan_stealth_scan("10.0.0.1",[22,80,443])
        self.assertEqual(len(p["ports"]),3)

class TestDecoy(unittest.TestCase):
    def test_generate(self):
        d=DecoyGenerator()
        r=d.generate_decoys(10)
        self.assertEqual(len(r),10)

if __name__=="__main__": unittest.main()
