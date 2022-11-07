#!/usr/bin/env python3
#
#  IRIS Source Code
#  DFIR-IRIS Team
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import datetime

from app.models import Cases
from app.models import Client
from app.models.authorization import User


def get_overview_db():
    """
    Get overview data from the database
    """
    open_cases = Cases.query.with_entities(
        Cases.case_id,
        Cases.case_uuid,
        Cases.name.label('case_title'),
        Cases.description.label('case_description'),
        Client.name.label('customer_name'),
        Cases.open_date.label('case_open_date'),
        User.name.label('opened_by')
    ).filter(
        Cases.close_date == None
    ).join(
        Cases.user,
        Cases.client
    ).all()

    open_cases_list = []
    for case in open_cases:
        c_case = case._asdict()
        c_case['case_open_since'] = f"{(datetime.date.today() - case.case_open_date).days} days"
        c_case['case_open_date'] = case.case_open_date.strftime('%d-%m-%Y')
        open_cases_list.append(c_case)

    return open_cases_list
