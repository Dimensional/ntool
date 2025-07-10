#!/usr/bin/python3
import sys
import logging
import argparse
from utils import *

def setup_logging(debug=False):
    """Configure logging based on debug flag"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(message)s'  # Simple format for output
    )

def create_parser():
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        description='Nintendo 3DS toolkit for CIA/CCI/NCCH manipulation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ntool.py srl_retail2dev game.nds --out game_dev.nds
  python3 ntool.py cia_dev2retail game.cia --out game_retail.cia
  python3 ntool.py cdn2cia cdn_folder --out game.cia --decrypt
  python3 ntool.py ncch_extractall game.ncch --dev
        """
    )
    
    # Global options
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output (shows detailed processing information)')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # SRL conversion
    srl_parser = subparsers.add_parser('srl_retail2dev', 
                                      help='Re-sign and re-encrypt NTR/TWL-enhanced/TWL-exclusive SRL for dev')
    srl_parser.add_argument('input', help='Path to input SRL file')
    srl_parser.add_argument('--out', help='Path to output file')
    
    # CIA conversion commands
    for cmd in ['cia_dev2retail', 'cia_retail2dev']:
        cia_parser = subparsers.add_parser(cmd, help=f'Convert CIA ({cmd.replace("_", " ")})')
        cia_parser.add_argument('input', help='Path to input CIA file')
        cia_parser.add_argument('--out', help='Path to output file')
    
    # CCI conversion commands  
    for cmd in ['cci_dev2retail', 'cci_retail2dev']:
        cci_parser = subparsers.add_parser(cmd, help=f'Convert CCI ({cmd.replace("_", " ")})')
        cci_parser.add_argument('input', help='Path to input CCI file')
        cci_parser.add_argument('--out', help='Path to output file')
    
    # CSU to retail CIAs
    csu_parser = subparsers.add_parser('csu2retailcias', help='Convert CSU to retail CIAs')
    csu_parser.add_argument('input', help='Path to input CSU file')
    csu_parser.add_argument('--out', help='Path to output directory')
    
    # CCI to CIA conversion
    cci2cia_parser = subparsers.add_parser('cci2cia', help='Convert CCI to CIA')
    cci2cia_parser.add_argument('input', help='Path to input CCI file')
    cci2cia_parser.add_argument('--out', help='Path to output CIA file')
    cci2cia_parser.add_argument('--cci-dev', action='store_true', help='Input CCI is dev-signed')
    cci2cia_parser.add_argument('--cia-dev', action='store_true', help='Output CIA should be dev-signed')
    
    # CDN to CIA conversion
    cdn2cia_parser = subparsers.add_parser('cdn2cia', help='Convert CDN contents to CIA')
    cdn2cia_parser.add_argument('input', help='Path to CDN folder')
    cdn2cia_parser.add_argument('--out', help='Path to output CIA file')
    cdn2cia_parser.add_argument('--title-ver', help='Title version to use')
    cdn2cia_parser.add_argument('--cdn-dev', action='store_true', help='CDN contents are dev-signed')
    cdn2cia_parser.add_argument('--cia-dev', action='store_true', help='Output CIA should be dev-signed')
    cdn2cia_parser.add_argument('--decrypt', action='store_true', help='Decrypt content files')
    
    # CIA to CDN conversion
    cia2cdn_parser = subparsers.add_parser('cia2cdn', help='Convert CIA to CDN contents')
    cia2cdn_parser.add_argument('input', help='Path to input CIA file')
    cia2cdn_parser.add_argument('--out', help='Path to output folder')
    cia2cdn_parser.add_argument('--titlekey', help='Title key to use')
    cia2cdn_parser.add_argument('--cia-dev', action='store_true', help='Input CIA is dev-signed')
    
    # CIA to CIA conversion (encrypt/decrypt)
    cia2cia_parser = subparsers.add_parser('cia2cia', help='Convert CIA encryption state (encrypt/decrypt)')
    cia2cia_parser.add_argument('input', help='Path to input CIA file')
    cia2cia_parser.add_argument('--out', help='Path to output CIA file')
    cia2cia_parser.add_argument('--cia-dev', action='store_true', help='Input CIA is dev-signed')
    cia2cia_parser.add_argument('--force-mode', choices=['encrypt', 'decrypt'], 
                               help='Force specific mode (default: auto-detect)')
    
    # Extract/rebuild commands
    for format_type in ['ncch', 'cia', 'cci']:
        for action in ['extractall', 'rebuildall']:
            cmd = f'{format_type}_{action}'
            help_text = f'{action.replace("all", " all components of")} {format_type.upper()}'
            
            cmd_parser = subparsers.add_parser(cmd, help=help_text)
            if action == 'extractall':
                cmd_parser.add_argument('input', help=f'Path to input {format_type.upper()} file')
            else:  # rebuildall
                cmd_parser.add_argument('input', help='Path to input folder')
            cmd_parser.add_argument('--dev', action='store_true', help='Use dev keys/signatures')
    
    return parser

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Set up logging based on debug flag
    setup_logging(args.debug)
    
    if not args.command:
        parser.print_help()
        return
    
    # Handle different command types
    if args.command in ['srl_retail2dev', 'cia_dev2retail', 'cia_retail2dev', 
                       'cci_dev2retail', 'cci_retail2dev', 'csu2retailcias']:
        func = globals()[args.command]
        func(args.input, args.out or '')
    
    elif args.command in ['ncch_extractall', 'ncch_rebuildall', 'cci_extractall', 
                         'cci_rebuildall', 'cia_extractall', 'cia_rebuildall']:
        func = globals()[args.command]
        func(args.input, 1 if args.dev else 0)
    
    elif args.command == 'cci2cia':
        cci2cia(args.input, args.out or '', 
               1 if args.cci_dev else 0, 
               1 if args.cia_dev else 0)
    
    elif args.command == 'cdn2cia':
        cdn2cia(args.input, args.out or '', args.title_ver or '',
               1 if args.cdn_dev else 0,
               1 if args.cia_dev else 0,
               1 if args.decrypt else 0)
    
    elif args.command == 'cia2cdn':
        cia2cdn(args.input, args.out or '', args.titlekey or '',
               1 if args.cia_dev else 0)
    
    elif args.command == 'cia2cia':
        cia2cia(args.input, args.out or '', 
               1 if args.cia_dev else 0,
               args.force_mode or '')

if __name__ == '__main__':
    main()
