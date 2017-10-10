import datetime

from django.db.models import F, Func, Value
from django.db.models.functions import Upper, Lower, Concat
from django.db import models

from operator import itemgetter
from collections import OrderedDict, defaultdict

from core.services import get_admin_account, delimit_filtervalue

from .services import check_lexical_convention, generate_kwargs_from_parsed_rule


class GET_VALUE(F):
    ADD = '->'


class ARRAY_APPEND(Func):
    function = 'array_append'


class ARRAY_REMOVE(Func):
    function = 'array_remove'


class UNNEST(Func):
    function = 'unnest'


class SKEYS(Func):
    function = 'skeys'


class REPLACE(Func):
    function = 'replace'


class DELETE(Func):
    function = 'delete'


def lowercase(text):
    return text.lower()


def uppercase(text):
    return text.upper()


def capitalize(text):
    return text.capitalize()


class YaraRuleQueryset(models.query.QuerySet):

    def active(self):
        return self.filter(status=self.model.ACTIVE_STATUS)

    def inactive(self):
        return self.filter(status=self.model.INACTIVE_STATUS)

    def pending(self):
        return self.filter(status=self.model.PENDING_STATUS)

    def rejected(self):
        return self.filter(status=self.model.REJECTED_STATUS)

    def has_dependencies(self):
        return self.filter(dependencies__len__gt=0)

    def has_missing_dependencies(self):
        missing_dependencies = self.missing_dependency_list()
        return self.has_dependencies().filter(dependencies__overlap=missing_dependencies)

    def category_list(self):
        return self.order_by('category').values_list('category', flat=True).distinct()

    def source_list(self):
        return self.order_by('source').values_list('source', flat=True).distinct()

    def submitter_list(self):
        return self.order_by('submitter').values_list('submitter__username', flat=True).distinct()

    def dependency_list(self):
        dependencies = list(self.annotate(dependency_elements=UNNEST('dependencies')).values_list('dependency_elements', flat=True).distinct())
        dependencies.sort()
        return dependencies

    def missing_dependency_list(self):
        dependency_list = self.dependency_list()
        available_dependencies = self.filter(name__in=dependency_list).values_list('name', flat=True).distinct()
        missing_dependencies = list(set(dependency_list) - set(available_dependencies))
        return missing_dependencies

    def tag_list(self):
        tags = list(self.annotate(tag_elements=UNNEST('tags')).values_list('tag_elements', flat=True).distinct())
        tags.sort(key=str.lower)
        return tags

    def metakey_list(self):
        metadata_keys = list(self.annotate(metadata_elements=SKEYS('metadata')).values_list('metadata_elements', flat=True).distinct())
        metadata_keys.sort(key=str.lower)
        return metadata_keys

    def import_list(self):
        imports = list(self.annotate(import_elements=UNNEST('imports')).values_list('import_elements', flat=True).distinct())
        imports.sort(key=str.lower)
        return imports

    def scope_list(self):
        scopes = list(self.annotate(scope_elements=UNNEST('scopes')).values_list('scope_elements', flat=True).distinct())
        scopes.sort(key=str.lower)
        return scopes

    def active_count(self):
        return self.active().count()

    def inactive_count(self):
        return self.inactive().count()

    def pending_count(self):
        return self.pending().count()

    def rejected_count(self):
        return self.rejected().count()

    def has_dependencies_count(self):
        return self.has_dependencies().count()

    def has_missing_dependencies_count(self):
        return self.has_missing_dependencies().count()

    def category_count(self):
        category_count = [(entry['category'], entry['count'])
                          for entry in self.order_by('category')
                          .values('category').annotate(count=models.Count('category'))]
        category_count.sort(key=itemgetter(0))
        ordered_category_count = OrderedDict((item[0], item[1]) for item in category_count)

        try:
            del ordered_category_count['']
        except KeyError:
            pass

        return ordered_category_count

    def source_count(self):
        source_count = [(entry['source'], entry['count'])
                        for entry in self.order_by('source')
                        .values('source').annotate(count=models.Count('source'))]
        source_count.sort(key=itemgetter(0))
        ordered_source_count = OrderedDict((item[0], item[1]) for item in source_count)

        try:
            del ordered_source_count['']
        except KeyError:
            pass

        return ordered_source_count

    def tag_count(self):
        tags = [(key, self.filter(tags__contains=[key]).count()) for key in self.tag_list()]
        tags.sort(key=itemgetter(0))
        tag_count = OrderedDict((item[0], item[1]) for item in tags)
        return tag_count

    def import_count(self):
        imports = [(key, self.filter(imports__contains=[key]).count()) for key in self.import_list()]
        imports.sort(key=itemgetter(0))
        imports = OrderedDict((item[0], item[1]) for item in imports)
        return imports

    def metakey_count(self):
        metadata_keys = [(key, self.filter(metadata__has_key=key).count()) for key in self.metakey_list()]
        metadata_keys.sort(key=itemgetter(0))
        metadata_keys = OrderedDict((item[0], item[1]) for item in metadata_keys)
        return metadata_keys

    def dependency_count(self):
        dependencies = [(key, self.filter(dependencies__contains=[key]).count()) for key in self.dependency_list()]
        dependencies.sort(key=itemgetter(0))
        dependency_count = OrderedDict((item[0], item[1]) for item in dependencies)
        return dependency_count

    def name_conflict_count(self):
        name_conflicts = [(entry['name'], entry['count'])
                          for entry in self.order_by('name').values('name')
                          .annotate(count=models.Count('name')).filter(count__gt=1)]
        name_conflicts.sort(key=itemgetter(0))
        name_conflicts = OrderedDict((item[0], item[1]) for item in name_conflicts)
        return name_conflicts

    def logic_collision_count(self):
        logic_conflicts = [(entry['logic_hash'], entry['count'])
                           for entry in self.order_by('logic_hash').values('logic_hash')
                           .annotate(count=models.Count('logic_hash')).filter(count__gt=1)]
        logic_conflicts.sort(key=itemgetter(0))
        logic_conflicts = OrderedDict((item[0], item[1]) for item in logic_conflicts)
        return logic_conflicts

    def missing_dependency_count(self):
        missing_dependencies = [(key, self.filter(dependencies__contains=[key]).count()) for key in self.missing_dependency_list()]
        missing_dependencies.sort(key=itemgetter(0))
        missing_dependencies = OrderedDict((item[0], item[1]) for item in missing_dependencies)
        return missing_dependencies

    # Bulk Update Methods
    def bulk_update(self, update_params):
        # Pass this to methods that return feedback in order to get unified message
        update_feedback = { 'errors': [], 'warnings': [], 'changes': [] }

        # Dynamically generate update method key value pairs
        metakey_list = self.metakey_list()
        metakey_update_methods = {'lowercase': {}, 'uppercase': {}, 'capitalize': {}, 'rename': {}}

        for metakey_value in metakey_list:
            metakey_update_methods['lowercase']['lowercase_metakey_{}'.format(metakey_value)] = metakey_value
            metakey_update_methods['uppercase']['uppercase_metakey_{}'.format(metakey_value)] = metakey_value
            metakey_update_methods['capitalize']['capitalize_metakey_{}'.format(metakey_value)] = metakey_value
            metakey_update_methods['rename']['rename_metakey_{}'.format(metakey_value)] = metakey_value

        # Perform updates for each update method specified
        for update_method in update_params:

            if update_method == 'update_category':
                category = update_params.get(update_method)
                self.update_category(category)

            elif update_method == 'update_source':
                source = update_params.get(update_method)
                self.update_source(source)

            elif update_method == 'update_status':
                status = update_params.get(update_method)
                self.update_status(status)

            elif update_method == 'add_tags':
                update_value = update_params.get(update_method)
                self.add_tags(update_value, update_feedback=update_feedback)

            elif update_method == 'remove_tags':
                update_value = update_params.get(update_method)
                self.remove_tags(update_value)

            elif update_method == 'remove_scopes':
                update_value = update_params.get(update_method)
                self.remove_scopes(update_value)

            elif update_method.startswith('set_metadata_'):
                metadata_key = update_method[update_method.index('set_metadata_') + 13:]
                metadata_value = update_params.get(update_method)
                self.set_metadata(metadata_key, metadata_value)

            elif update_method == 'remove_metadata':
                update_value = update_params.get(update_method)
                self.remove_metadata(update_value)

            elif update_method == 'lowercase_name':
                update_value = update_params.get(update_method)
                self.change_name_case('lowercase', modifier=update_value)

            elif update_method == 'uppercase_name':
                update_value = update_params.get(update_method)
                self.change_name_case('uppercase', modifier=update_value)

            elif update_method == 'append_name':
                update_value = update_params.get(update_method)
                self.append_name(update_value)

            elif update_method == 'prepend_name':
                update_value = update_params.get(update_method)
                self.prepend_name(update_value)

            elif update_method == 'remove_name':
                update_value = update_params.get(update_method)
                self.remove_name(update_value)

            elif update_method in metakey_update_methods['lowercase']:
                update_value = update_params.get(update_method)
                metakey = metakey_update_methods['lowercase'][update_method]
                self.change_metakey_case(metakey, 'lowercase', modifier=update_value)

            elif update_method in metakey_update_methods['uppercase']:
                update_value = update_params.get(update_method)
                metakey = metakey_update_methods['uppercase'][update_method]
                self.change_metakey_case(metakey, 'uppercase', modifier=update_value)

            elif update_method in metakey_update_methods['capitalize']:
                update_value = update_params.get(update_method)
                metakey = metakey_update_methods['capitalize'][update_method]
                self.change_metakey_case(metakey, 'capitalize', modifier=update_value)

            elif update_method in metakey_update_methods['rename']:
                update_value = update_params.get(update_method)
                metakey = metakey_update_methods['rename'][update_method]
                self.rename_metakey(metakey, update_value)

            else:
                continue

        return update_feedback

    def update_category(self, category):
        queryset_owners = self.values_list('owner', flat=True).distinct()

        if len(queryset_owners) == 1:
            group = self[:1].get().owner

            if category in group.groupmeta.category_options:
                self.update(category=category)

    def update_source(self, source):
        queryset_owners = self.values_list('owner', flat=True).distinct()

        if len(queryset_owners) == 1:
            group = self[:1].get().owner

            if source in group.groupmeta.source_options:
                self.update(source=source)

    def update_status(self, status):
        if status in ('active', 'inactive', 'pending', 'rejected'):
            self.update(status=status)

    def add_tags(self, tag_elements, update_feedback=None):
        if isinstance(tag_elements, str):
            tag_elements = delimit_filtervalue(tag_elements)

        if not update_feedback:
            update_feedback = { 'warnings': [], 'changes': [] }

        for tag_value in tag_elements:
            if check_lexical_convention(tag_value):
                self.exclude(tags__overlap=[tag_value]).update(tags=ARRAY_APPEND('tags', Value(tag_value)))
                msg = 'Added Tag: {}'.format(tag_value)
                update_feedback['changes'].append(msg)
            else:
                msg = 'Skipped Invalid Tag: {}'.format(tag_value)
                update_feedback['warnings'].append(msg)

        return update_feedback

    def remove_tags(self, tag_elements):
        if isinstance(tag_elements, str):
            tag_elements = delimit_filtervalue(tag_elements)

        for tag_value in tag_elements:
            self.filter(tags__overlap=[tag_value]).update(tags=ARRAY_REMOVE('tags', Value(tag_value)))

    def remove_scopes(self, scope_elements):
        if isinstance(scope_elements, str):
            scope_elements = delimit_filtervalue(scope_elements)

        for scope_value in scope_elements:
            print(scope_value)
            self.filter(scopes__overlap=[scope_value]).update(scopes=ARRAY_REMOVE('scopes', Value(scope_value)))

    def change_name_case(self, operation, modifier=None):
        available_operations = {'lowercase': lowercase,
                                'uppercase': uppercase}

        edit = available_operations.get(operation, None)

        if edit and modifier:
            modification = edit(modifier)
            self.update(name=REPLACE('name', Value(modifier), Value(modification)))

        elif operation == 'lowercase':
            self.update(name=Lower('name'))

        elif operation == 'uppercase':
            self.update(name=Upper('name'))

    def remove_metadata(self, metadata_elements):
        if isinstance(metadata_elements, str):
            metadata_elements = delimit_filtervalue(metadata_elements)

        for metadata_value in metadata_elements:
            self.filter(metadata__has_key=metadata_value).update(metadata=DELETE('metadata', Value(metadata_value)))

    def change_metakey_case(self, metakey, operation, modifier=None):
        available_operations = {'lowercase': lowercase,
                                'uppercase': uppercase,
                                'capitalize': capitalize}

        edit = available_operations.get(operation, None)

        if edit:

            if modifier:
                new_metakey = metakey.replace(modifier, edit(modifier))
            else:
                new_metakey = edit(metakey)

            # Copy old metadata into an hstore container with new key value
            TEMP_HSTORE = Func(Value(new_metakey), GET_VALUE('metadata') + Value(metakey), function='hstore')

            # Delete old key entry from original hstore
            META_HSTORE = Func(F('metadata'), Value(metakey), function='delete')

            # Combine the two hstores using internal 'hs_concat' function
            CONCAT_HSTORE = Func(TEMP_HSTORE, META_HSTORE, function='hs_concat')

            self.filter(metadata__has_key=metakey).update(metadata=CONCAT_HSTORE)

    def rename_metakey(self, old_metakey, new_metakey):

        if check_lexical_convention(new_metakey):
            # Copy old metadata into an hstore container with new key value
            TEMP_HSTORE = Func(Value(new_metakey), GET_VALUE('metadata') + Value(old_metakey), function='hstore')

            # Delete old key entry from original hstore
            META_HSTORE = Func(F('metadata'), Value(old_metakey), function='delete')

            # Combine the two hstores using internal 'hs_concat' function
            CONCAT_HSTORE = Func(TEMP_HSTORE, META_HSTORE, function='hs_concat')

            self.filter(metadata__has_key=old_metakey).update(metadata=CONCAT_HSTORE)

    def append_name(self, modifier):
        invalid_modifications = []

        # Ensure name manipulation does not create an invalid rule name
        for entry_id, entry_name in self.values_list('id', 'name'):
            new_name = entry_name + modifier

            if not check_lexical_convention(new_name):
                invalid_modifications.append(entry_id)

        self.exclude(id__in=invalid_modifications).update(name=Concat('name', Value(modifier)))

    def prepend_name(self, modifier):
        invalid_modifications = []

        # Ensure name manipulation does not create an invalid rule name
        for entry_id, entry_name in self.values_list('id', 'name'):
            new_name = modifier + entry_name

            if not check_lexical_convention(new_name):
                invalid_modifications.append(entry_id)

        self.exclude(id__in=invalid_modifications).update(name=Concat(Value(modifier), 'name'))

    def remove_name(self, pattern):
        invalid_modifications = []

        # Ensure name manipulation does not create an invalid rule name
        for entry_id, entry_name in self.values_list('id', 'name'):
            new_name = entry_name.replace(pattern, '')

            if not check_lexical_convention(new_name):
                invalid_modifications.append(entry_id)

        self.exclude(id__in=invalid_modifications).update(name=REPLACE('name', Value(pattern), Value('')))

    def set_metadata(self, metakey, metavalue):

        if check_lexical_convention(metakey) and \
        (metavalue.isdigit() or metavalue in ('true', 'false') or \
        (metavalue.startswith('\"') and metavalue.endswith('\"'))):

            # Copy old metadata into an hstore container with new key value
            TEMP_HSTORE = Func(Value(metakey), Value(metavalue), function='hstore')

            # Delete old key entry from original hstore
            META_HSTORE = Func(F('metadata'), Value(metakey), function='delete')

            # Combine the two hstores using internal 'hs_concat' function
            CONCAT_HSTORE = Func(TEMP_HSTORE, META_HSTORE, function='hs_concat')

            self.update(metadata=CONCAT_HSTORE)

    def deconflict_logic(self, update_feedback=None):
        if not update_feedback:
            update_feedback = { 'warnings': [], 'changes': [] }

        deconflict_count = 0
        logic_mapping = defaultdict(list)

        # Group rules with same logic
        for rule in self:
            logic_mapping[rule.logic_hash].append(rule)

        for logic_hash, rules in logic_mapping.items():
            # Check if there was actually a collision
            if len(rules) == 1:
                continue

            newrule = None

            for rule in rules:
                if not newrule:
                    newrule = rule
                else:
                    for tag in rule.tags:
                        if tag not in newrule.tags:
                            newrule.tags.append(tag)

                    for scope in rule.scopes:
                        if scope not in newrule.scopes:
                            newrule.scopes.append(scope)

                    for imp in rule.imports:
                        if imp not in newrule.imports:
                            newrule.imports.append(imp)

                    for key, value in rule.metadata.items():
                        if key not in newrule.metadata:
                            newrule.metadata[key] = value

                    for comment in rule.yararulecomment_set.all():
                        comment.rule = newrule
                        comment.save()

                    rule.delete()
                    deconflict_count += 1

            newrule.save()

        if deconflict_count == 0:
            update_feedback['warnings'].append('No rules to deconflict')

        elif deconflict_count == 1:
            update_feedback['changes'].append('Deconflicted 1 rule')

        else:
            msg = 'Deconflicted {} Rules'.format(deconflict_count)
            update_feedback['changes'].append(msg)

        return update_feedback


class YaraRuleManager(models.Manager):

    def get_queryset(self):
        return YaraRuleQueryset(self.model, using=self._db)

    def category_options(self, group):
        return group.groupmeta.category_options

    def source_options(self, group):
        return group.groupmeta.source_options

    def process_parsed_rules(self, rules, source, category, submitter, owner, status='active',
                             add_tags=None, add_metadata=None, prepend_name=None, append_name=None,
                             force_source=False, force_category=False):
        # Container for results
        feedback = {'errors': [],
                    'warnings': [],
                    'rule_upload_count': 0,
                    'rule_collision_count': 0}

        # Ensure specified source is valid
        if not owner.groupmeta.source_required and not source:
            pass
        elif owner.groupmeta.source_required and not source:
            feedback['errors'].append('No Source Specified')
        elif source not in owner.groupmeta.source_options:
            if force_source:
                owner.groupmeta.source_options.append(source)
                owner.groupmeta.save()
            else:
                feedback['errors'].append('Invalid Source Specified: {}'.format(source))

        # Ensure specified category is valid
        if not owner.groupmeta.category_required and not category:
            pass
        elif owner.groupmeta.category_required and not category:
            feedback['errors'].append('No Category Specified')
        elif category not in owner.groupmeta.category_options:
            if force_category:
                owner.groupmeta.category_options.append(category)
                owner.groupmeta.save()
            else:
                feedback['errors'].append('Invalid Category Specified: {}'.format(category))

        # Rules must have a non-anonymous submitter and must not have pre-processing errors
        if not submitter.is_anonymous() and not feedback['errors']:

            prepend_conflicts = 0
            append_conflicts = 0

            for rule in rules:
                rule_kwargs = generate_kwargs_from_parsed_rule(rule)
                rule_kwargs['owner'] = owner
                rule_kwargs['submitter'] = submitter
                rule_kwargs['source'] = source
                rule_kwargs['category'] = category
                rule_kwargs['status'] = status

                # Pop comments from kwargs so they don't get processed prematurely
                comments = rule_kwargs.pop('comments')

                # Process Modifications
                if add_tags:
                    if isinstance(add_tags, str):
                        add_tags = delimit_filtervalue(add_tags)

                    for tag_value in add_tags:
                        if check_lexical_convention(tag_value):
                            if tag_value not in rule_kwargs['tags']:
                                rule_kwargs['tags'].append(tag_value)
                        else:
                            msg = 'Skipped Invalid Tag: {}'.format(tag_value)

                            if msg not in feedback['warnings']:
                                feedback['warnings'].append(msg)

                if add_metadata:
                    for metakey, metavalue in add_metadata.items():
                        if check_lexical_convention(metakey) and \
                        (metavalue.isdigit() or metavalue in ('true', 'false') or \
                        (metavalue.startswith('\"') and metavalue.endswith('\"'))):
                            rule_kwargs['metadata'][metakey] = metavalue
                        else:
                            msg = 'Skipped Invalid Metadata: {}'.format(metakey)

                            if msg not in feedback['warnings']:
                                feedback['warnings'].append(msg)

                if prepend_name:
                    new_name = prepend_name + rule_kwargs['name']

                    if check_lexical_convention(new_name):
                        rule_kwargs['name'] = new_name
                    else:
                        prepend_conflicts += 1

                if append_name:
                    new_name = rule_kwargs['name'] + append_name

                    if check_lexical_convention(new_name):
                        rule_kwargs['name'] = new_name
                    else:
                        append_conflicts += 1

                # Check for rules with exact same detection logic
                if self.filter(owner=owner, logic_hash=rule_kwargs['logic_hash']).exists():
                    feedback['rule_collision_count'] += 1
                else:
                    new_rule = self.create(**rule_kwargs)
                    new_rule.save()

                    # Process extracted comments
                    new_rule.yararulecomment_set.model.objects.process_extracted_comments(new_rule, comments)

                    feedback['rule_upload_count'] += 1

            # Check to see if any name manipulation conflicts occurred for feedback
            if prepend_conflicts:
                msg = 'Unable To Prepend {} Rule Names'.format(prepend_conflicts)
                feedback['warnings'].append(msg)

            if append_conflicts:
                msg = 'Unable To Append {} Rule Names'.format(append_conflicts)
                feedback['warnings'].append(msg)

        return feedback


class YaraRuleCommentManager(models.Manager):

    def process_extracted_comments(self, rule, comments):
        # Generate comments from parsed comment data
        for comment in comments:
            comment_data = {'created': datetime.datetime.now(),
                            'modified': datetime.datetime.now(),
                            'poster': get_admin_account(),
                            'content': comment, 'rule': rule}

            self.create(**comment_data)