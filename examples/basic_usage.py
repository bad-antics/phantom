from phantom.core import PhantomScanner,DecoyGenerator
s=PhantomScanner()
for st in ["syn","fin","xmas","null"]: print(f"{st}: {s.get_scan_info(st)['description']}")
plan=s.plan_stealth_scan("10.0.0.1",[22,80,443,8080])
print(f"\nScan plan: {plan['evasion_options']}")
d=DecoyGenerator()
print(f"Decoys: {d.generate_decoys(5)}")
