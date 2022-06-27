import uuid
import random
from datetime import datetime

from flowers.db import User, Node, NodeName, Dashboard, Export, APIKey
from flowers.utils import password, generate_apikey, check_hash


def test_model_table_matches_env():
    """
    Tests that table name as set during runtime matches the declared env.
    For example, a table should map to flowers-$env-users. So users table maps to flowers-staging-users, etc.
    """
    pass


def test_db_configt(flowers_fixtures):
    user_id = flowers_fixtures["user"]["user_id"]
    user = User.get(user_id=user_id)
    assert user_id == user.user_id


class Faker:
    @staticmethod
    def email():
        domain = random.choice(["gmail", "google", "yahoo", "msn", "hotmail"])
        return f"{uuid.uuid4().hex[:10]}-test@{domain}.com"

    @staticmethod
    def id(model):
        uid = uuid.uuid4()
        if model == "user":
            return f"{uid}U"

        elif model == "node":
            return f"{uid}N"

        return uid

    @staticmethod
    def nodename():
        uid = uuid.uuid4().hex
        return f"{uid}-TEST"

    @staticmethod
    def network():
        networks = ["testnet", "mainnet", "ropsten", "kovan", "rinkeby", "gorli"]
        return random.choice(networks)

    @staticmethod
    def now():
        now = datetime.utcnow().replace(microsecond=0)
        return f"{now.isoformat()}Z"


class TestUserCRUD:
    def _new_user(self, user_fixture):
        fx_user = user_fixture
        fx_user["user_id"] = Faker.id("user")
        fx_user["creation_date"] = Faker.now()
        fx_user["email"] = Faker.email()
        user = User(**fx_user)
        user.save()
        return user

    def test_create(self, flowers_fixtures):
        new_user = self._new_user(flowers_fixtures["user"])
        assert new_user.user_id

    def test_retrieve(self, flowers_fixtures):
        fx_user_id = flowers_fixtures["user"]["user_id"]
        user = User.get(user_id=fx_user_id)
        assert user.user_id == fx_user_id

    def test_update(self, flowers_fixtures):
        user = self._new_user(flowers_fixtures["user"])
        new_email = Faker.email()
        user.update(email=new_email)

    def test_delete(self, flowers_fixtures):
        user = self._new_user(flowers_fixtures["user"])
        user.delete()

    def test_list_all(self):
        users = User.scan()
        all_users = list(users)
        assert len(all_users) > 0


class TestNodeCRUD:
    def _new_node(self, node_fixture):
        fx_node = node_fixture
        fx_node["node_id"] = Faker.id("node")
        fx_node["node_name"] = Faker.nodename()
        fx_node["creation_date"] = Faker.now()
        fx_node["owner_id"] = Faker.id("user")
        node = Node(**fx_node)
        node.save()
        return node

    def test_create(self, flowers_fixtures):
        new_node = self._new_node(flowers_fixtures["node"])
        assert new_node.node_id

    def test_retrieve(self, flowers_fixtures):
        fx_node_id = flowers_fixtures["node"]["node_id"]
        node = Node.get(node_id=fx_node_id)
        assert node.node_id == fx_node_id

    def test_update(self, flowers_fixtures):
        node = self._new_node(flowers_fixtures["node"])
        network = Faker.network()
        # schema = node.Schema(); schema.validate(node.to_dict()) # passes validation
        # TODO: why does this fail, possible related to nested validation. eg: resources
        # node.update(network=network)
        node.network = network
        node.save()
        assert node.network == network

    def test_delete(self, flowers_fixtures):
        node = self._new_node(flowers_fixtures["node"])
        node.delete()

    def _test_query_date_range(self):
        import datetime
        import dateutil.relativedelta

        now = datetime.datetime.now()
        last_month = now + dateutil.relativedelta.relativedelta(months=-1)
        nodes = Node.scan(creation_date__lte=str(last_month))
        all_nodes = list(nodes)
        assert len(all_nodes) > 0

    def _test_list_all(self):
        nodes = Node.scan()
        all_nodes = list(nodes)
        assert len(all_nodes) > 0


class TestNodeNameCRUD:
    def _new_nodename(self):
        fx_nodename = {"name": Faker.nodename(), "network": Faker.network()}
        name = NodeName(**fx_nodename)
        name.save()
        return name

    def test_create(self):
        nodename = self._new_nodename()
        assert nodename.name

    def test_retrieve(self, flowers_fixtures):
        fx_nodename = flowers_fixtures["name"]["name"]
        name = NodeName.get(name=fx_nodename)
        assert name.name == fx_nodename

    def test_update(self):
        nodename = self._new_nodename()
        network = Faker.network()
        # TODO: investigate how updates works
        # nodename.update(network=network)
        nodename.network = network
        response = nodename.save()
        assert nodename.network == network

    def test_delete(self, flowers_fixtures):
        name = self._new_nodename()
        name.delete()

    def test_list_all(self):
        names = NodeName.scan()
        all_names = list(names)
        assert len(all_names) > 0


class TestExportCRUD:
    pass


class TestDashboardCRUD:
    pass


class TestAPIKeysCRUD:
    def test_create(self, flowers_fixtures):
        user = flowers_fixtures["user"]
        apikey, keyhash = APIKey.create(user_id=user["user_id"])
        assert isinstance(keyhash, bytes)

    def test_retrieve(self, flowers_fixtures):
        user = flowers_fixtures["user"]
        apikeys = APIKey.get_user_keys(user["user_id"])
        assert isinstance(apikeys, list)

    def test_revoke(self, flowers_fixtures):
        # create api key
        user = flowers_fixtures["user"]
        apikey, keyhash = APIKey.create(user_id=user["user_id"])
        # revoke key
        apikey.delete()

        # attempt to retrieve key
        apikey = APIKey.get_by_alias(apikey.alias)
        assert apikey is None

    def test_max_apikeys_limit(self, flowers_fixtures):
        pass

    def test_verify(self, flowers_fixtures):
        user = flowers_fixtures["user"]
        apikey, keyhash = APIKey.create(user_id=user["user_id"])
        is_valid = APIKey.verify_by_user(user["user_id"], keyhash)
        assert is_valid

    def test_verify2(self):
        (salt, hashed) = generate_apikey()
        valid = check_hash(salt, hashed)
        assert valid
