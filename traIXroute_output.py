# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis and George Nomikos
#
# This file is part of traIXroute.
#
# traIXroute is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# traIXroute is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with traIXroute.  If not, see <http://www.gnu.org/licenses/>.

import os,socket,string_handler
import json

'''
Handles all the prints.
'''

class traIXroute_output():


    '''
    Prints the number of the extracted IXP IP addresses and Subnets from each dataset before and after merging.
    Input:
        a) peering_ixp2asn: A dictionary with {IXP IP}=[ASN] extracted from peeringdb.
        b) peering_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] extracted from peeringdb. 
        c) pch_ixp2asn: A dictionary with {IXP IP}=[ASN] extracted from pch.
        d) pch_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] extracted from pch.
        e) final_ixp2asn: A dictionary with {IXP IP}=[ASN] after merging pch, peeringdb and user's data.
        f) final_sub2name: A dictionary with {Subnet}=[IXP long name, IXP short name] after merging pch, peeringdb and user's data.
        g) dirty_ips: A dictionary with {IXP IP}=[ASN]. It is about dirty IXP IPs-to-ASNs. 
        h) additional_ip2asn: A dictionary with {IXP IP}=[ASN], imported from the user.
        i) additional_subnet2name: A dictionary with {IXP Subnet}=[IXP long name, IXP short name], imported from the user.
        j) lenreserved: The number of the imported reserved subnets.
    '''
    def print_db_stats(self,peering_ixp2asn,peering_sub2name,pch_ixp2asn,pch_sub2name,final_ixp2asn,final_sub2name,dirty_ips,additional_ip2asn,additional_subnet2name,lenreserved):
        print('Imported '+ str(lenreserved)+' Reserved Subnets.')  
        print('Extracted '+ str(len(additional_ip2asn.keys()))+' IXP IPs from additional_info.txt.')
        print('Extracted '+ str(len(additional_subnet2name.keys()))+' IXP Subnets from additional_info.txt.')        
        print('Extracted '+ str(len(peering_ixp2asn.keys()))+' IXP IPs from PDB.')
        print('Extracted '+ str(len(pch_ixp2asn.keys()))+' IXP IPs from PCH.')
        print('Extracted '+ str(len(peering_sub2name.keys()))+' IXP Subnets from PDB.')
        print('Extracted '+ str(len(pch_sub2name.keys()))+' IXP Subnets from PCH.')
        print('Extracted '+ str(len(final_ixp2asn.keys()))+' not dirty IXP IPs after merging PDB, PCH and additional_info.txt.')
        print('Extracted '+ str(len(dirty_ips.keys()))+' dirty IXP IPs after merging PDB, PCH and additional_info.txt.')
        print('Extracted '+ str(len(final_sub2name.keys()))+' IXP Subnets after merging PDB, PCH and additional_info.txt.')

    '''
    Prints the number of extracted rules.
    Input:
        a) final_rules: The list containing the rules.
        b) file: The file containing the rules.
    '''
    def print_rules_number(self,final_rules,file):
        print("Imported "+str(len(final_rules))+" IXP Detection Rules from "+file+".")           

    def print_ripe(self,cur_ixp_long,cur_ixp_short,cur_path_asn,tr,i,j,num,ixp_short,ixp_long,cur_asmt):
        path=tr["ip_path"]
        msm_id = tr["msm_id"]
        src_prb_id = tr["src_prb_id"]
        dst_prb_id = tr["dst_prb_id"]

        rule=''
        
        gra_asn=['' for x in cur_path_asn]
        ixp_string=['' for x in cur_ixp_short]
        for pointer in range(0,len(ixp_string)):
            if len(ixp_short)>i+pointer-1:
                if ixp_short[i+pointer-1]!='Not IXP':
                    if ixp_short[i+pointer-1]!='':
                        ixp_string[pointer]=ixp_short[i+pointer-1]  
                    else:
                        ixp_string[pointer]=ixp_long[i+pointer-1]
        asm_a=ixp_string[0]
        if ixp_string[0]!='' and ixp_string[1]!='' and  ixp_string[0]!=ixp_string[1]:
            asm_a=asm_a+','
        if ixp_string[1]!='' and ixp_string[0]!=ixp_string[1]:
            asm_a=asm_a+ixp_string[1]
        if len(ixp_string)>2:
            asm_b=ixp_string[1]
            if ixp_string[1]!='' and ixp_string[2]!='' and ixp_string[2]!=ixp_string[1]:
                asm_b=asm_b+','
            if ixp_string[2]!=''  and ixp_string[1]!=ixp_string[2]:
                asm_b=asm_b+ixp_string[2]

        entry_ixp = []

        JEDI_RESULT_DIR = "/home/santiago/src/ixp-country-jedi/UG/results/"
        JEDI_RESULT_FILE = os.path.abspath(JEDI_RESULT_DIR+"/msm."+str(msm_id)+".json")

        with open(JEDI_RESULT_FILE, mode='r') as fjedijson:
            jedidata = json.load(fjedijson)

        if 'a' in cur_asmt:
            temp_print=rule+str(i)+') ' +path[i-1]+gra_asn[0]+' <--- '+asm_a+' ---> '+str(i+1)+') '+path[i]+gra_asn[1]
            entry_ixp.append({'hop': str(i), 'name': asm_a, 'link': 0, 'in_country': True })
            print(temp_print)

            if 'aorb' in cur_asmt:
                temp_print=' or '+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
                entry_ixp.append({'hop': str(i+1), 'name': asm_b, 'link': 2, 'in_country': True })
                print(temp_print)
            if 'aandb' in cur_asmt:
                temp_print=('and ('+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2])
                entry_ixp.append({'hop': str(i+1), 'name': asm_b, 'link': 3, 'in_country': True })
                print(temp_print)
        elif 'b' in cur_asmt:
            temp_print=rule+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
            entry_ixp.append({'hop': str(i+1), 'name': asm_b, 'link': 1, 'in_country': True })
            print(temp_print)

        # TODO: before dumping, check if traixroute doesn't exist yet
        for jd in jedidata :
            if jd.__contains__("src_prb_id") and jd.__contains__("dst_prb_id"):
                if jd["src_prb_id"] == src_prb_id : 
                    jd["traixroute"] = entry_ixp
        with open(JEDI_RESULT_FILE, mode='w') as f:
            json.dump([], f)
        with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
            json.dump(jedidata, fjedijson, indent=2)
