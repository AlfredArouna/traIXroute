# Copyright (C) 2016 Santiago R.R. <santiagorr@riseup.net>
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

import os
import json

class dataStore():

    def __init__(self):
        self.ripe_traixroute_file = ""
        self.traixroutejason = []
        self.jediresults = {}

    """
    Reads a ripe traIXroute processed file
    """
    def load_ripe (self, ripe_traixroute_file):
        self.ripe_traixroute_file = ripe_traixroute_file
        with open(ripe_traixroute_file, 'r') as outfile:
            self.traixroutejason = json.load(outfile)

    def get_ripe (self):
        return self.traixroutejason 

    def load_jediresults (self, msm_id):
        JEDI_RESULT_DIR = os.path.dirname(self.ripe_traixroute_file) + "/results"
        JEDI_RESULT_FILE = os.path.abspath(JEDI_RESULT_DIR+"/msm."+str(msm_id)+".json")
        print ("jedi_result: " + JEDI_RESULT_FILE)
        try:
            with open(JEDI_RESULT_FILE, mode='r') as fjedijson:
                jedidata = json.load(fjedijson)
            self.jediresults[msm_id] = jedidata
        except:
            print ("Possibly empty file" + JEDI_RESULT_FILE)

    def get_jediresults (self, msm_id):
        try:
            return self.jediresults[msm_id]
        except:
            return {}

    def addJediData(self, msm_id, src_prb_id, dst_prb_id, entry_ixp):
        # TODO: before dumping, check if traixroute doesn't exist yet
        for jd in self.jediresults[msm_id] :
            if jd.__contains__("src_prb_id") and jd.__contains__("dst_prb_id"):
                if jd["src_prb_id"] == src_prb_id and jd["dst_prb_id"] == dst_prb_id :
                    jd["traixroute"] = entry_ixp

    def save_traixed_jedi(self, msm_id):
        JEDI_RESULT_DIR = os.path.dirname(self.ripe_traixroute_file) + "/results"
        JEDI_RESULT_FILE = os.path.abspath(JEDI_RESULT_DIR+"/msm."+str(msm_id)+".json")

        if (self.jediresults.__contains__(msm_id)):
            with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
                json.dump([], fjedijson)
            with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
                json.dump(self.jediresults[msm_id], fjedijson, indent=2)
