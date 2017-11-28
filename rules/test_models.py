import re
from django.test import TestCase

from .models import YaraRule
from .testing_core import generate_test_user


class YaraRuleSearchTestCase(TestCase):
    """ Test custom search methods, managers, and querysets for YaraRule model """

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user(username='RULETESTER')
        cls.group = cls.user.groups.get()

        cls.source_options = ['Internal Source', 'External Submission', 'Reporting']
        cls.category_options = ['Binary', 'Memory']

        cls.collision_hash = '79437f5edda13f9c0669b978dd7a9066dd2059f1'

        cls.group.groupmeta.source_options = cls.source_options
        cls.group.groupmeta.category_options = cls.category_options
        cls.group.groupmeta.save()

        YaraRule.objects.create(name='ActiveRule',
                                strings={},
                                condition=[],
                                tags=['Tag1', 'Tag2'],
                                scopes=['private'],
                                imports=['\"pe\"'],
                                metadata={'author': '\"Johnny Test\"',
                                          'description': '\"Incredible Rule\"'},
                                dependencies=[],
                                logic_hash=cls.collision_hash,
                                owner=cls.group,
                                submitter=cls.user,
                                source='Internal Source',
                                category='Binary',
                                status=YaraRule.ACTIVE_STATUS)

        YaraRule.objects.create(name='InactiveRule',
                                strings={},
                                condition=[],
                                tags=['Tag2', 'Tag3'],
                                scopes=[],
                                imports=['\"pe\"', '\"math\"'],
                                metadata={'author': '\"John Test\"',
                                          'description': '\"Incredible Rule\"'},
                                dependencies=[],
                                logic_hash=cls.collision_hash,
                                owner=cls.group,
                                submitter=cls.user,
                                source='Internal Source',
                                category='Binary',
                                status=YaraRule.INACTIVE_STATUS)

        YaraRule.objects.create(name='PendingRule',
                                strings={},
                                condition=[],
                                tags=['Tag3'],
                                scopes=[],
                                imports=['\"pe\"'],
                                metadata={'dependent': 'true'},
                                dependencies=['ActiveRule'],
                                logic_hash='10864888334a37c31f983675d72f4db601e30d20',
                                owner=cls.group,
                                submitter=cls.user,
                                source='External Submission',
                                category='Binary',
                                status=YaraRule.PENDING_STATUS)

        YaraRule.objects.create(name='RejectedRule',
                                strings={},
                                condition=[],
                                tags=['Tag4'],
                                scopes=['global'],
                                imports=[],
                                metadata={'description': '\"Terrible Rule\"'},
                                dependencies=['MissingRule'],
                                logic_hash='a0d597a713a39ac31bca73708c9779b07c57871e',
                                owner=cls.group,
                                submitter=cls.user,
                                source='Reporting',
                                category='Memory',
                                status=YaraRule.REJECTED_STATUS)

        YaraRule.objects.create(name='ActiveRule',
                                strings={},
                                condition=[],
                                tags=[],
                                scopes=['private'],
                                imports=[],
                                metadata={'description': '\"Duplicate Name Rule\"'},
                                dependencies=[],
                                logic_hash='a0d597b714a39aca1bca43a08c9779b07c57871e',
                                owner=cls.group,
                                submitter=cls.user,
                                source='Internal Source',
                                category='Memory',
                                status=YaraRule.ACTIVE_STATUS)

        cls.queryset = YaraRule.objects.all()

    ### Begin Queryset Method Tests ###
    def test_queryset_method_active(self):
        self.assertEqual('ActiveRule', self.queryset.active()[:1].get().name)

    def test_queryset_method_inactive(self):
        self.assertEqual('InactiveRule', self.queryset.inactive().get().name)

    def test_queryset_method_pending(self):
        self.assertEqual('PendingRule', self.queryset.pending().get().name)

    def test_queryset_method_rejected(self):
        self.assertEqual('RejectedRule', self.queryset.rejected().get().name)

    def test_queryset_method_active_count(self):
        self.assertEqual(2, self.queryset.active().count())

    def test_queryset_method_category_count(self):
        category_count = self.queryset.category_count()
        self.assertEqual(3, category_count['Binary'])
        self.assertEqual(2, category_count['Memory'])

    def test_queryset_method_dependency_count(self):
        dependency_count = self.queryset.dependency_count()
        self.assertEqual(1, dependency_count['ActiveRule'])
        self.assertEqual(1, dependency_count['MissingRule'])

    def test_queryset_method_has_dependencies_count(self):
        self.assertEqual(2, self.queryset.has_dependencies_count())

    def test_queryset_method_has_missing_dependencies_count(self):
        self.assertEqual(1, self.queryset.has_missing_dependencies_count())

    def test_queryset_method_import_count(self):
        import_count = self.queryset.import_count()
        self.assertEqual(3, import_count['\"pe\"'])
        self.assertEqual(1, import_count['\"math\"'])

    def test_queryset_method_inactive_count(self):
        self.assertEqual(1, self.queryset.inactive().count())

    def test_queryset_method_logic_collision_count(self):
        collision_count = self.queryset.logic_collision_count()
        self.assertEqual(2, collision_count[self.collision_hash])

    def test_queryset_method_metakey_count(self):
        metakey_count = self.queryset.metakey_count()
        self.assertEqual(1, metakey_count['dependent'])
        self.assertEqual(2, metakey_count['author'])
        self.assertEqual(4, metakey_count['description'])

    def test_queryset_method_missing_dependency_count(self):
        dependency_count = self.queryset.missing_dependency_count()
        self.assertEqual(1, dependency_count['MissingRule'])

    def test_queryset_method_name_conflict_count(self):
        conflict_count = self.queryset.name_conflict_count()
        self.assertEqual(2, conflict_count['ActiveRule'])

    def test_queryset_method_pending_count(self):
        self.assertEqual(1, self.queryset.pending().count())

    def test_queryset_method_rejected_count(self):
        self.assertEqual(1, self.queryset.rejected().count())

    def test_queryset_method_source_count(self):
        source_count = self.queryset.source_count()
        self.assertEqual(1, source_count['External Submission'])
        self.assertEqual(3, source_count['Internal Source'])
        self.assertEqual(1, source_count['Reporting'])

    def test_queryset_method_tag_count(self):
        tag_count = self.queryset.tag_count()
        self.assertEqual(1, tag_count['Tag1'])
        self.assertEqual(2, tag_count['Tag2'])
        self.assertEqual(2, tag_count['Tag3'])
        self.assertEqual(1, tag_count['Tag4'])

    def test_queryset_method_category_list(self):
        expected_categories = ['Binary', 'Memory']

        category_list = self.queryset.category_list()
        self.assertEqual(len(expected_categories), len(category_list))

        for category in expected_categories:
            self.assertIn(category, category_list)

    def test_queryset_method_dependency_list(self):
        expected_dependencies = ['ActiveRule', 'MissingRule']

        dependency_list = self.queryset.dependency_list()
        self.assertEqual(len(expected_dependencies), len(dependency_list))

        for dependency in expected_dependencies:
            self.assertIn(dependency, dependency_list)

    def test_queryset_method_import_list(self):
        expected_imports = ['\"math\"', '\"pe\"']

        import_list = self.queryset.import_list()
        self.assertEqual(len(expected_imports), len(import_list))

        for imp in expected_imports:
            self.assertIn(imp, import_list)

    def test_queryset_method_metakey_list(self):
        expected_metakeys = ['author', 'dependent', 'description']

        metakey_list = self.queryset.metakey_list()
        self.assertEqual(len(expected_metakeys), len(metakey_list))

        for metakey in expected_metakeys:
            self.assertIn(metakey, metakey_list)

    def test_queryset_method_missing_dependency_list(self):
        expected_dependencies = ['MissingRule']

        dependency_list = self.queryset.missing_dependency_list()
        self.assertEqual(len(expected_dependencies), len(dependency_list))

        for dependency in expected_dependencies:
            self.assertIn(dependency, dependency_list)

    def test_queryset_method_scope_list(self):
        expected_scopes = ['global', 'private']

        scope_list = self.queryset.scope_list()
        self.assertEqual(len(expected_scopes), len(scope_list))

        for scope in expected_scopes:
            self.assertIn(scope, scope_list)

    def test_queryset_method_source_list(self):
        expected_sources = ['External Submission', 'Internal Source', 'Reporting']

        source_list = self.queryset.source_list()
        self.assertEqual(len(expected_sources), len(source_list))

        for source in expected_sources:
            self.assertIn(source, source_list)

    def test_queryset_method_submitter_list(self):
        expected_submitters = ['RULETESTER']

        submitter_list = self.queryset.submitter_list()
        self.assertEqual(len(expected_submitters), len(submitter_list))

        for submitter in expected_submitters:
            self.assertIn(submitter, submitter_list)

    def test_queryset_method_tag_list(self):
        expected_tags = ['Tag1', 'Tag2', 'Tag3', 'Tag4']

        tag_list = self.queryset.tag_list()
        self.assertEqual(len(expected_tags), len(tag_list))

        for tag in expected_tags:
            self.assertIn(tag, tag_list)

    def test_queryset_method_has_dependencies(self):
        self.assertEqual(2, self.queryset.has_dependencies().count())

    def test_queryset_method_has_missing_dependencies(self):
        self.assertEqual(1, self.queryset.has_missing_dependencies().count())

    ### Begin Manager Method Tests ###
    def test_manager_method_category_options(self):
        category_options = YaraRule.objects.category_options(self.group)
        self.assertEqual(len(self.category_options), len(category_options))

        for category in self.category_options:
            self.assertIn(category, category_options)

    def test_manager_method_source_options(self):
        source_options = YaraRule.objects.source_options(self.group)
        self.assertEqual(len(self.source_options), len(source_options))

        for source in self.source_options:
            self.assertIn(source, source_options)


class YaraRuleEditingTestCase(TestCase):
    """ Test custom editing methods, managers, and querysets for YaraRule model """

    def setUp(self):

        YaraRule.objects.create(name='EditRule1',
                                strings={},
                                condition=[],
                                tags=['OldTag1', 'OldTag2'],
                                scopes=['private'],
                                imports=[],
                                metadata={'Author': '\"John Test\"',
                                          'Description': '\"Editing Rule\"',
                                          'URL': '\"https://www.google.com\"'},
                                dependencies=[],
                                logic_hash='',
                                owner=self.group,
                                submitter=self.user,
                                source='Reporting',
                                category='Memory',
                                status=YaraRule.ACTIVE_STATUS)

        YaraRule.objects.create(name='EditRule2',
                                strings={},
                                condition=[],
                                tags=['OldTag2', 'OldTag3'],
                                scopes=['global'],
                                imports=[],
                                metadata={'Author': '\"Johnny Test\"',
                                          'URL': '\"https://www.bing.com\"'},
                                dependencies=[],
                                logic_hash='',
                                owner=self.group,
                                submitter=self.user,
                                source='Internal Source',
                                category='PCAP',
                                status=YaraRule.INACTIVE_STATUS)

        self.queryset = YaraRule.objects.all()

    @classmethod
    def setUpTestData(cls):
        cls.user = generate_test_user()
        cls.group = cls.user.groups.get()

        cls.source_options = ['Internal Source', 'Reporting']
        cls.category_options = ['Binary', 'Memory', 'PCAP']

        cls.group.groupmeta.source_options = cls.source_options
        cls.group.groupmeta.category_options = cls.category_options
        cls.group.groupmeta.save()

    ### Begin Queryset Method Tests ###
    def test_queryset_method_add_tags_with_list(self):
        new_tags = ['NewListTag1', 'NewListTag2']
        invalid_tags = ['1', 'global']

        self.queryset.add_tags(new_tags + invalid_tags)

        for entry in self.queryset:
            for tag in new_tags:
                self.assertIn(tag, entry.tags)
            for tag in invalid_tags:
                self.assertNotIn(tag, entry.tags)

    def test_queryset_method_add_tags_with_string(self):
        new_tags = ['NewStringTag1', 'NewStringTag2']
        invalid_tags = ['9', 'private']

        self.queryset.add_tags(','.join(new_tags + invalid_tags))

        for entry in self.queryset:
            for tag in new_tags:
                self.assertIn(tag, entry.tags)
            for tag in invalid_tags:
                self.assertNotIn(tag, entry.tags)

    def test_queryset_method_append_name_with_invalid_value(self):
        invalid_append_value = '$'
        self.queryset.append_name(invalid_append_value)

        for entry in self.queryset:
            assert not entry.name.endswith(invalid_append_value)

    def test_queryset_method_append_name_with_valid_value(self):
        valid_append_value = '_appended'
        self.queryset.append_name(valid_append_value)

        for entry in self.queryset:
            assert entry.name.endswith(valid_append_value)

    def test_queryset_method_change_metakey_case_to_lowercase(self):
        self.queryset.change_metakey_case('URL', 'lowercase')

        for entry in self.queryset:
            self.assertNotIn('URL', entry.metadata)
            self.assertIn('url', entry.metadata)

    def test_queryset_method_change_metakey_case_to_partial_lowercase(self):
        self.queryset.change_metakey_case('URL', 'lowercase', modifier='RL')

        for entry in self.queryset:
            self.assertNotIn('URL', entry.metadata)
            self.assertIn('Url', entry.metadata)

    def test_queryset_method_change_metakey_case_to_uppercase(self):
        self.queryset.change_metakey_case('Author', 'uppercase')

        for entry in self.queryset:
            self.assertNotIn('Author', entry.metadata)
            self.assertIn('AUTHOR', entry.metadata)

    def test_queryset_method_change_metakey_case_to_partial_uppercase(self):
        self.queryset.change_metakey_case('Author', 'uppercase', modifier='Auth')

        for entry in self.queryset:
            self.assertNotIn('Author', entry.metadata)
            self.assertIn('AUTHor', entry.metadata)

    def test_queryset_method_change_metakey_case_to_capitalized(self):
        self.queryset.change_metakey_case('URL', 'capitalize')

        for entry in self.queryset:
            self.assertNotIn('URL', entry.metadata)
            self.assertIn('Url', entry.metadata)

    def test_queryset_method_change_metakey_case_to_partial_capitalized(self):
        self.queryset.change_metakey_case('Author', 'capitalize', modifier='thor')

        for entry in self.queryset:
            self.assertNotIn('Author', entry.metadata)
            self.assertIn('AuThor', entry.metadata)

    def test_queryset_method_change_name_case_to_lowercase(self):
        self.queryset.change_name_case('lowercase')

        for entry in self.queryset:
            for value in entry.name:
                if value.isalpha():
                    self.assertTrue(value.islower())

    def test_queryset_method_change_name_case_to_partial_lowercase(self):
        partial_value = 'Rule'
        pattern = r"({}|{})".format(partial_value, partial_value.lower())
        self.queryset.change_name_case('lowercase', modifier=partial_value)

        for entry in self.queryset:
            matches = re.findall(pattern, entry.name)
            self.assertNotIn(partial_value, matches)

    def test_queryset_method_change_name_case_to_uppercase(self):
        self.queryset.change_name_case('uppercase')

        for entry in self.queryset:
            for value in entry.name:
                if value.isalpha():
                    self.assertTrue(value.isupper())

    def test_queryset_method_change_name_case_to_partial_uppercase(self):
        partial_value = 'Edit'
        pattern = r"({}|{})".format(partial_value, partial_value.upper())
        self.queryset.change_name_case('uppercase', modifier=partial_value)

        for entry in self.queryset:
            matches = re.findall(pattern, entry.name)
            self.assertNotIn(partial_value, matches)

    def test_queryset_method_prepend_name_with_invalid_value(self):
        self.queryset.prepend_name('1')

        for entry in self.queryset:
            assert not entry.name.startswith('1')

    def test_queryset_method_prepend_name_with_valid_value(self):
        self.queryset.prepend_name('Prepended')

        for entry in self.queryset:
            assert entry.name.startswith('Prepended')

    def test_queryset_method_remove_metadata_with_list(self):
        removed_metadata = ['Author', 'Description']

        self.queryset.remove_metadata(removed_metadata)

        for entry in self.queryset:
            for metadata in removed_metadata:
                self.assertNotIn(metadata, entry.metadata)

    def test_queryset_method_remove_metadata_with_string(self):
        removed_metadata = ['Author', 'Description']

        self.queryset.remove_metadata(','.join(removed_metadata))

        for entry in self.queryset:
            for metadata in removed_metadata:
                self.assertNotIn(metadata, entry.metadata)

    def test_queryset_method_remove_name_with_invalid_value(self):
        self.queryset.remove_name('EditRule')

        for entry in self.queryset:
            self.assertIn(entry.name, ['EditRule1', 'EditRule2'])

    def test_queryset_method_remove_name_with_valid_value(self):
        self.queryset.remove_name('Edit')

        for entry in self.queryset:
            self.assertIn(entry.name, ['Rule1', 'Rule2'])

    def test_queryset_method_remove_tags_with_list(self):
        removed_tags = ['OldTag1', 'OldTag2', 'RandomTag']

        self.queryset.remove_tags(removed_tags)

        for entry in self.queryset:
            for tag in removed_tags:
                self.assertNotIn(tag, entry.tags)

    def test_queryset_method_remove_tags_with_string(self):
        removed_tags = ['OldTag2', 'OldTag3', 'RandomTag']

        self.queryset.remove_tags(','.join(removed_tags))

        for entry in self.queryset:
            for tag in removed_tags:
                self.assertNotIn(tag, entry.tags)

    def test_queryset_method_remove_scopes_with_list(self):
        removed_scopes = ['private', 'global']

        self.queryset.remove_scopes(removed_scopes)

        for entry in self.queryset:
            for scope in removed_scopes:
                self.assertNotIn(scope, entry.scopes)

    def test_queryset_method_remove_scopes_with_string(self):
        removed_scopes = ['private', 'global']

        self.queryset.remove_scopes(','.join(removed_scopes))

        for entry in self.queryset:
            for scope in removed_scopes:
                self.assertNotIn(scope, entry.scopes)

    def test_queryset_method_rename_metakey_with_invalid_value(self):
        invalid_value = '!Link'
        self.queryset.rename_metakey('URL', invalid_value)

        for entry in self.queryset:
            self.assertNotIn(invalid_value, entry.metadata)

    def test_queryset_method_rename_metakey_with_valid_value(self):
        self.queryset.rename_metakey('URL', 'Link')

        for entry in self.queryset:
            self.assertNotIn('URL', entry.metadata)
            self.assertIn('Link', entry.metadata)
            self.assertIn(entry.metadata['Link'], ['\"https://www.google.com\"',
                                                   '\"https://www.bing.com\"'])

    def test_queryset_method_set_metadata_with_invalid_key_value(self):
        invalid_key_value = '#invalid'
        valid_entry_value = '\"New Value\"'
        self.queryset.set_metadata(invalid_key_value, valid_entry_value)

        for entry in self.queryset:
            self.assertNotIn(invalid_key_value, entry.metadata)

    def test_queryset_method_set_metadata_with_invalid_entry_value(self):
        valid_key_value = 'NewKey'
        invalid_entry_value = 'Invalid Value'
        self.queryset.set_metadata(valid_key_value, invalid_entry_value)

        for entry in self.queryset:
            self.assertNotIn(valid_key_value, entry.metadata)

    def test_queryset_method_set_metadata_with_valid_values(self):
        valid_key_value = 'NewKey'
        valid_entry_value = '\"New Value\"'
        self.queryset.set_metadata(valid_key_value, valid_entry_value)

        for entry in self.queryset:
            self.assertIn(valid_key_value, entry.metadata)
            self.assertEqual(entry.metadata[valid_key_value], valid_entry_value)

    def test_queryset_method_set_metadata_with_valid_value_overwrite(self):
        valid_key_value = 'Author'
        valid_entry_value = '\"Real Author\"'
        self.queryset.set_metadata(valid_key_value, valid_entry_value)

        for entry in self.queryset:
            self.assertIn(valid_key_value, entry.metadata)
            self.assertEqual(entry.metadata[valid_key_value], valid_entry_value)

    def test_queryset_method_update_category_with_invalid_value(self):
        invalid_value = 'Non-existent Category'
        self.queryset.update_category(invalid_value)

        for entry in self.queryset:
            self.assertNotEqual(invalid_value, entry.category)

    def test_queryset_method_update_category_with_valid_value(self):
        valid_value = self.category_options[0]
        self.queryset.update_category(valid_value)

        for entry in self.queryset:
            self.assertEqual(valid_value, entry.category)

    def test_queryset_method_update_source_with_invalid_value(self):
        invalid_value = 'Non-existent Source'
        self.queryset.update_source(invalid_value)

        for entry in self.queryset:
            self.assertNotEqual(invalid_value, entry.source)

    def test_queryset_method_update_source_with_valid_value(self):
        valid_value = self.source_options[0]
        self.queryset.update_source(valid_value)

        for entry in self.queryset:
            self.assertEqual(valid_value, entry.source)

    def test_queryset_method_update_status_with_invalid_value(self):
        invalid_value = 'Non-existent Status'
        self.queryset.update_status(invalid_value)

        for entry in self.queryset:
            self.assertNotEqual(invalid_value, entry.status)

    def test_queryset_method_update_status_with_valid_value(self):
        valid_value = YaraRule.PENDING_STATUS
        self.queryset.update_status(valid_value)

        for entry in self.queryset:
            self.assertEqual(valid_value, entry.status)

    ### Begin Manager Method Tests ###
    def test_manager_method_process_parsed_rules(self):
        pass # TO-DO
