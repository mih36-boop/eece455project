"""Run A and C in one process, with a pause for the intervening slides."""
import argparse, runpy
from pathlib import Path
from part_c_demo import run

def main():
    p=argparse.ArgumentParser(); p.add_argument('--auto',action='store_true',help='Run without pauses for testing'); args=p.parse_args()
    if not args.auto: input('Slides 3–4: press Enter to start Part A...')
    print('\nPART A | SLIDES 3–6 | Key generation, verification, integrity')
    ctx=runpy.run_path(str(Path(__file__).with_name('part_a_demo.py')))
    print('\nReturn to slides 5–8: explain tampering, avalanche effect and hashing.')
    if not args.auto: input('After slides 9–10, press Enter to continue to Part C...')
    run({k:ctx[k] for k in ('pub','msg','sig')},live=not args.auto)
    print('\nReturn to slide 11: applications and conclusion.')
if __name__=='__main__': main()
