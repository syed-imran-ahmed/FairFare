from lyft_rides.auth import ClientCredentialGrant
from lyft_rides.session import Session
from lyft_rides.client import LyftRidesClient

auth_flow = ClientCredentialGrant(
    client_id="YAoc10HPt3YZ", client_secret="1I3WOpilktUG3jRUrP_wKyDX0KPkYn1j", scopes='public')
session = auth_flow.get_session()

client = LyftRidesClient(session)
# response = client.get_ride_types(37.7833, -122.4167)
# response = client.get_cost_estimates(slat, slon, elat, elon)
# ride_types = response.json.get('ride_types')
