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

    def print_ripe(self,cur_ixp_long,cur_ixp_short,cur_path_asn,tr,i,j,num,ixp_short,ixp_long,cur_asmt,ripe,ixp_cc,cc):
        path=tr["ip_path"]
        msm_id = tr["msm_id"]
        src_prb_id = tr["src_prb_id"]
        dst_prb_id = tr["dst_prb_id"]
        ripe_traixroute_file = ripe

        rule=''
        
        for tmp_cc in ixp_cc:
            if len(tmp_cc) > 2:
                tmp_cc = country2cc[tmp_cc]

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

        JEDI_RESULT_DIR = os.path.dirname(ripe_traixroute_file) + "/results"
        JEDI_RESULT_FILE = os.path.abspath(JEDI_RESULT_DIR+"/msm."+str(msm_id)+".json")


        with open(JEDI_RESULT_FILE, mode='r') as fjedijson:
            jedidata = json.load(fjedijson)

        if 'a' in cur_asmt:
            temp_print=rule+str(i)+') ' +path[i-1]+gra_asn[0]+' <--- '+asm_a+' ---> '+str(i+1)+') '+path[i]+gra_asn[1]
            entry_ixp.append({'hop': str(i), 'name': asm_a, 'link': 0, 'in_country': ixp_cc[i] == cc })
            print(entry_ixp)

            if 'aorb' in cur_asmt:
                temp_print=' or '+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
                entry_ixp.append({'hop': str(i+1), 'name': asm_b, 'link': 2, 'in_country': ixp_cc[i] == cc })
                print(entry_ixp)
            if 'aandb' in cur_asmt:
                temp_print=('and ('+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2])
                entry_ixp.append({'hop': str(i+1), 'name': asm_b, 'link': 3, 'in_country': ixp_cc[i] == cc })
                print(entry_ixp)
        elif 'b' in cur_asmt:
            temp_print=rule+str(i+1)+') ' +path[i]+gra_asn[1]+' <--- '+asm_b+' ---> '+str(i+2)+') '+path[i+1]+gra_asn[2]
            entry_ixp.append({'hop': str(i+1), 'name': asm_b, 'link': 1, 'in_country': ixp_cc[i] == cc })
            print(entry_ixp)

        # TODO: before dumping, check if traixroute doesn't exist yet
        for jd in jedidata :
            if jd.__contains__("src_prb_id") and jd.__contains__("dst_prb_id"):
                if jd["src_prb_id"] == src_prb_id : 
                    jd["traixroute"] = entry_ixp

        with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
            json.dump([], fjedijson)
        with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
            json.dump(jedidata, fjedijson, indent=2)

country2cc = {
 'Afghanistan': 'AF',
 'Albania': 'AL',
 'Algeria': 'DZ',
 'American Samoa': 'AS',
 'Andorra': 'AD',
 'Angola': 'AO',
 'Anguilla': 'AI',
 'Antarctica': 'AQ',
 'Antigua and Barbuda': 'AG',
 'Argentina': 'AR',
 'Armenia': 'AM',
 'Aruba': 'AW',
 'Australia': 'AU',
 'Austria': 'AT',
 'Azerbaijan': 'AZ',
 'Bahamas': 'BS',
 'Bahrain': 'BH',
 'Bangladesh': 'BD',
 'Barbados': 'BB',
 'Belarus': 'BY',
 'Belgium': 'BE',
 'Belize': 'BZ',
 'Benin': 'BJ',
 'Bermuda': 'BM',
 'Bhutan': 'BT',
 'Bolivia, Plurinational State of': 'BO',
 'Bonaire, Sint Eustatius and Saba': 'BQ',
 'Bosnia and Herzegovina': 'BA',
 'Botswana': 'BW',
 'Bouvet Island': 'BV',
 'Brazil': 'BR',
 'British Indian Ocean Territory': 'IO',
 'Brunei Darussalam': 'BN',
 'Bulgaria': 'BG',
 'Burkina Faso': 'BF',
 'Burundi': 'BI',
 'Cambodia': 'KH',
 'Cameroon': 'CM',
 'Canada': 'CA',
 'Cape Verde': 'CV',
 'Cayman Islands': 'KY',
 'Central African Republic': 'CF',
 'Chad': 'TD',
 'Chile': 'CL',
 'China': 'CN',
 'Christmas Island': 'CX',
 'Cocos (Keeling) Islands': 'CC',
 'Colombia': 'CO',
 'Comoros': 'KM',
 'Congo': 'CG',
 'Congo, the Democratic Republic of the': 'CD',
 'Cook Islands': 'CK',
 'Costa Rica': 'CR',
 'Country name': 'Code',
 'Croatia': 'HR',
 'Cuba': 'CU',
 'Curaçao': 'CW',
 'Cyprus': 'CY',
 'Czech Republic': 'CZ',
 "Côte d'Ivoire": 'CI',
 'Denmark': 'DK',
 'Djibouti': 'DJ',
 'Dominica': 'DM',
 'Dominican Republic': 'DO',
 'Ecuador': 'EC',
 'Egypt': 'EG',
 'El Salvador': 'SV',
 'Equatorial Guinea': 'GQ',
 'Eritrea': 'ER',
 'Estonia': 'EE',
 'Ethiopia': 'ET',
 'Falkland Islands (Malvinas)': 'FK',
 'Faroe Islands': 'FO',
 'Fiji': 'FJ',
 'Finland': 'FI',
 'France': 'FR',
 'French Guiana': 'GF',
 'French Polynesia': 'PF',
 'French Southern Territories': 'TF',
 'Gabon': 'GA',
 'Gambia': 'GM',
 'Georgia': 'GE',
 'Germany': 'DE',
 'Ghana': 'GH',
 'Gibraltar': 'GI',
 'Greece': 'GR',
 'Greenland': 'GL',
 'Grenada': 'GD',
 'Guadeloupe': 'GP',
 'Guam': 'GU',
 'Guatemala': 'GT',
 'Guernsey': 'GG',
 'Guinea': 'GN',
 'Guinea-Bissau': 'GW',
 'Guyana': 'GY',
 'Haiti': 'HT',
 'Heard Island and McDonald Islands': 'HM',
 'Holy See (Vatican City State)': 'VA',
 'Honduras': 'HN',
 'Hong Kong': 'HK',
 'Hungary': 'HU',
 'ISO 3166-2:GB': '(.uk)',
 'Iceland': 'IS',
 'India': 'IN',
 'Indonesia': 'ID',
 'Iran, Islamic Republic of': 'IR',
 'Iraq': 'IQ',
 'Ireland': 'IE',
 'Isle of Man': 'IM',
 'Israel': 'IL',
 'Italy': 'IT',
 'Jamaica': 'JM',
 'Japan': 'JP',
 'Jersey': 'JE',
 'Jordan': 'JO',
 'Kazakhstan': 'KZ',
 'Kenya': 'KE',
 'Kiribati': 'KI',
 "Korea, Democratic People's Republic of": 'KP',
 'Korea, Republic of': 'KR',
 'Kuwait': 'KW',
 'Kyrgyzstan': 'KG',
 "Lao People's Democratic Republic": 'LA',
 'Latvia': 'LV',
 'Lebanon': 'LB',
 'Lesotho': 'LS',
 'Liberia': 'LR',
 'Libya': 'LY',
 'Liechtenstein': 'LI',
 'Lithuania': 'LT',
 'Luxembourg': 'LU',
 'Macao': 'MO',
 'Macedonia, the former Yugoslav Republic of': 'MK',
 'Madagascar': 'MG',
 'Malawi': 'MW',
 'Malaysia': 'MY',
 'Maldives': 'MV',
 'Mali': 'ML',
 'Malta': 'MT',
 'Marshall Islands': 'MH',
 'Martinique': 'MQ',
 'Mauritania': 'MR',
 'Mauritius': 'MU',
 'Mayotte': 'YT',
 'Mexico': 'MX',
 'Micronesia, Federated States of': 'FM',
 'Moldova, Republic of': 'MD',
 'Monaco': 'MC',
 'Mongolia': 'MN',
 'Montenegro': 'ME',
 'Montserrat': 'MS',
 'Morocco': 'MA',
 'Mozambique': 'MZ',
 'Myanmar': 'MM',
 'Namibia': 'NA',
 'Nauru': 'NR',
 'Nepal': 'NP',
 'Netherlands': 'NL',
 'New Caledonia': 'NC',
 'New Zealand': 'NZ',
 'Nicaragua': 'NI',
 'Niger': 'NE',
 'Nigeria': 'NG',
 'Niue': 'NU',
 'Norfolk Island': 'NF',
 'Northern Mariana Islands': 'MP',
 'Norway': 'NO',
 'Oman': 'OM',
 'Pakistan': 'PK',
 'Palau': 'PW',
 'Palestine, State of': 'PS',
 'Panama': 'PA',
 'Papua New Guinea': 'PG',
 'Paraguay': 'PY',
 'Peru': 'PE',
 'Philippines': 'PH',
 'Pitcairn': 'PN',
 'Poland': 'PL',
 'Portugal': 'PT',
 'Puerto Rico': 'PR',
 'Qatar': 'QA',
 'Romania': 'RO',
 'Russian Federation': 'RU',
 'Rwanda': 'RW',
 'Réunion': 'RE',
 'Saint Barthélemy': 'BL',
 'Saint Helena, Ascension and Tristan da Cunha': 'SH',
 'Saint Kitts and Nevis': 'KN',
 'Saint Lucia': 'LC',
 'Saint Martin (French part)': 'MF',
 'Saint Pierre and Miquelon': 'PM',
 'Saint Vincent and the Grenadines': 'VC',
 'Samoa': 'WS',
 'San Marino': 'SM',
 'Sao Tome and Principe': 'ST',
 'Saudi Arabia': 'SA',
 'Senegal': 'SN',
 'Serbia': 'RS',
 'Seychelles': 'SC',
 'Sierra Leone': 'SL',
 'Singapore': 'SG',
 'Sint Maarten (Dutch part)': 'SX',
 'Slovakia': 'SK',
 'Slovenia': 'SI',
 'Solomon Islands': 'SB',
 'Somalia': 'SO',
 'South Africa': 'ZA',
 'South Georgia and the South Sandwich Islands': 'GS',
 'South Sudan': 'SS',
 'Spain': 'ES',
 'Sri Lanka': 'LK',
 'Sudan': 'SD',
 'Suriname': 'SR',
 'Svalbard and Jan Mayen': 'SJ',
 'Swaziland': 'SZ',
 'Sweden': 'SE',
 'Switzerland': 'CH',
 'Syrian Arab Republic': 'SY',
 'Taiwan, Province of China': 'TW',
 'Tajikistan': 'TJ',
 'Tanzania, United Republic of': 'TZ',
 'Thailand': 'TH',
 'Timor-Leste': 'TL',
 'Togo': 'TG',
 'Tokelau': 'TK',
 'Tonga': 'TO',
 'Trinidad and Tobago': 'TT',
 'Tunisia': 'TN',
 'Turkey': 'TR',
 'Turkmenistan': 'TM',
 'Turks and Caicos Islands': 'TC',
 'Tuvalu': 'TV',
 'Uganda': 'UG',
 'Ukraine': 'UA',
 'United Arab Emirates': 'AE',
 'United Kingdom': 'GB',
 'United States': 'US',
 'United States Minor Outlying Islands': 'UM',
 'Uruguay': 'UY',
 'Uzbekistan': 'UZ',
 'Vanuatu': 'VU',
 'Venezuela, Bolivarian Republic of': 'VE',
 'Viet Nam': 'VN',
 'Virgin Islands, British': 'VG',
 'Virgin Islands, U.S.': 'VI',
 'Wallis and Futuna': 'WF',
 'Western Sahara': 'EH',
 'Yemen': 'YE',
 'Zambia': 'ZM',
 'Zimbabwe': 'ZW',
 'Åland Islands': 'AX'}
