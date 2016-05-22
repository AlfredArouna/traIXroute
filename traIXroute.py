# Copyright (C) 2016 Institute of Computer Science of the Foundation for Research and Technology - Hellas (FORTH)
# Authors: Michalis Bamiedakis and George Nomikos
#
# Contact Email: gnomikos [at] ics.forth.gr
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

import sys
import os
import path_info_extraction as _Pif
import download_files as _Dl
import detection_rules as _Dr
import database_extract as _De
import json
import click 

@click.command()
@click.option('-r','--ripe',type=str)
@click.option('-u','--update',type=bool,default=False)
def traIXroute(ripe,update):
	mypath=sys.path[0]

	if update or (not os.path.exists(mypath+'/database')):
		if update:
			print ('Updating the database...')
		else:
			print ('Downloading the database...')
		download_helper = _Dl.download_files()
		outcome = download_helper.download_files(mypath)
		if outcome:
			print ('Finished successfully.')
		else:
			print ('Error occured. Exiting...')
			exit(0)

	if ripe:
		detection_helper = _Dr.detection_rules()
		path_helper = _Pif.path_info_extraction()
		mydb = _De.database()

		_rules = detection_helper.rules_extract('rules.txt')
		_datasets = mydb.dbextract(mypath) 

		with open(ripe,'r') as outfile:
			traceroutes = json.load(outfile)
			for tr in traceroutes:
				ip_path = tr['ip_path']
				_pathInfo = path_helper.path_info_extraction(_datasets, ip_path)
				detection_helper.resolve_ripe(tr, _rules, _pathInfo, _datasets[3], mypath)
				break

if __name__ == "__main__":
	traIXroute()
