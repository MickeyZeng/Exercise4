from git import Repo
import re
import numpy as np


def summary_lines(difflines):
    pattern = re.compile('@@')
    return [s for s in difflines if pattern.match(s)]

def parse_summary(summary):
    bits = summary.split(' ')
    delBit = bits[1].split(',')
    addBit = bits[2].split(',')
    delStart = -int(delBit[0])
    if len(delBit) == 1:
        delLength = 1
    else:
        delLength = int(delBit[1])
    addStart = int(addBit[0])
    if len(addBit) == 1:
        addLength = 1
    else:
        addLength = int(addBit[1])
    return (delStart, delLength, addStart, addLength)

def find_enclosing_scope(delStart, delLength, addStart, addLength, fileContents):
    # first scan forward from delStart+delLength-1 until we find more closing braces than opening
    lineNum = delStart-1
    numOpen = 1
    while numOpen > 0:
        lineNum += 1
        if lineNum >= len(fileContents):
            lineNum = len(fileContents) - 1
            break
        line = fileContents[lineNum]
        #print('f:' + line)
        for c in line:
            if c == '}':
                numOpen -= 1
                if numOpen == 0:
                    break
            if c == '{':
                numOpen += 1
    scopeEnd = lineNum+1
    # now scan backwards from same spot
    lineNum = delStart
    # print('s:'+fileContents[lineNum])
    numOpen = 1
    while numOpen > 0:
        lineNum -= 1
        if lineNum < 0:
            lineNum = 0
            break
        line = fileContents[lineNum]
        #print('b:' + line)
        for c in line[::-1]:
            if c == '{':
                numOpen -= 1
                if numOpen == 0:
                    break
            if c == '}':
                numOpen += 1
    scopeStart = lineNum+1
    return (scopeStart, scopeEnd)


# in a list of blame messages, find the one with the most recent commit
def find_most_recent_commit(blames):
    commits = []
    times = []
    for b in blames:
        tmp = b.split()
        commits += [tmp[0]]
        times += [int(tmp[3])]
    return commits[np.argmax(times)]


# find the Vulnerability-Contributing Commit(s)
def find_vcc(repo_path, fixing_commit, blame_opt='-w'):
    # create repo object from path
    repo = Repo(repo_path)
    HEAD = fixing_commit
    PREV = fixing_commit + '^'

    # find all of the files changed
    files = repo.git.diff('--name-only', PREV, HEAD).splitlines()

    commitsFound = []
    for file in files:
        print('------------------------------File: ' + file)
        # check file exists in PREV - if not then skip
        # read in the previous version of the file
        try:
            # we need the file contents to find the enclosing scope
            fileContents = repo.git.show(PREV+':'+file).splitlines()
        except:
            # file must be new in HEAD, so does not contribute to VCC
            continue
        # find the lines that are different, by looking for @@ -a,b +c,d @@
        difflines = repo.git.diff('-U0', PREV, HEAD, file).splitlines()
        summlines = summary_lines(difflines)
        for line in summlines:
            # print(line)
            # parse the numbers
            (delStart, delLength, addStart, addLength) = parse_summary(line)
            ##print("delStart, delLength, addStart, addLength: ",delStart, delLength, addStart, addLength)
            # if there are deleted lines, find the blamed commit(s)
            if delLength > 0:
                blames = repo.git.blame(blame_opt, '--date=unix', '-e', '-f', '-L '+str(
                    delStart) + ',' + str(delStart + delLength - 1), PREV, file).splitlines()
                commit = find_most_recent_commit(blames)
                ##print('Commit: '+commit)
                # add one for each line deleted
                commitsFound += [commit]*delLength
            # if there are added lines, find the enclosing scope and then find the commits
            if addLength > 0:
                (scopeStart, scopeEnd) = find_enclosing_scope(
                    delStart, delLength, addStart, addLength, fileContents)
                blames = repo.git.blame(blame_opt, '--date=unix', '-e', '-f', '-L '+str(
                    scopeStart) + ',' + str(scopeEnd), PREV, file).splitlines()
                commit = find_most_recent_commit(blames)
                ##print('Commit: '+commit)
                # add once for each line added
                commitsFound += [commit]*addLength

    # now find the most common entry in commitsFound
    mostCommonCommit = max(set(commitsFound), key=commitsFound.count)
    print(commitsFound)
    return mostCommonCommit

    def user_agent(self, value):
        """
        Sets user agent.
        """
        self.default_headers['User-Agent'] = value

    def set_default_header(self, header_name, header_value):
        self.default_headers[header_name] = header_value

    def __call_api(self, resource_path, method,
                   path_params=None, query_params=None, header_params=None,
                   body=None, post_params=None, files=None,
                   response_type=None, auth_settings=None,
                   _return_http_data_only=None, collection_formats=None, _preload_content=True,
                   _request_timeout=None):

        config = self.configuration

        # header parameters
        header_params = header_params or {}
        header_params.update(self.default_headers)
        if self.cookie:
            header_params['Cookie'] = self.cookie
        if header_params:
            header_params = self.sanitize_for_serialization(header_params)
            header_params = dict(self.parameters_to_tuples(header_params,
                                                           collection_formats))

        # path parameters
        if path_params:
            path_params = self.sanitize_for_serialization(path_params)
            path_params = self.parameters_to_tuples(path_params,
                                                    collection_formats)
            for k, v in path_params:
                # specified safe chars, encode everything
                resource_path = resource_path.replace(
                    '{%s}' % k, quote(str(v), safe=config.safe_chars_for_path_param))

        # query parameters
        if query_params:
            query_params = self.sanitize_for_serialization(query_params)
            query_params = self.parameters_to_tuples(query_params,
                                                     collection_formats)

        # post parameters
        if post_params or files:
            post_params = self.prepare_post_parameters(post_params, files)
            post_params = self.sanitize_for_serialization(post_params)
            post_params = self.parameters_to_tuples(post_params,
                                                    collection_formats)

        # auth setting
        self.update_params_for_auth(header_params, query_params, auth_settings)

        # body
        if body:
            body = self.sanitize_for_serialization(body)

        # request url
        url = self.configuration.host + resource_path

        # perform request and return response
        response_data = self.request(method, url,
                                     query_params=query_params,
                                     headers=header_params,
                                     post_params=post_params, body=body,
                                     _preload_content=_preload_content,
                                     _request_timeout=_request_timeout)

        self.last_response = response_data

        return_data = response_data
        if _preload_content:
            # deserialize response data
            if response_type:
                return_data = self.deserialize(response_data, response_type)
            else:
                return_data = None

        if _return_http_data_only:
            return (return_data)
        else:
            return (return_data, response_data.status, response_data.getheaders())

    def sanitize_for_serialization(self, obj):
        """
        Builds a JSON POST object.
        If obj is None, return None.
        If obj is str, int, long, float, bool, return directly.
        If obj is datetime.datetime, datetime.date
            convert to string in iso8601 format.
        If obj is list, sanitize each element in the list.
        If obj is dict, return the dict.
        If obj is swagger model, return the properties dict.
        :param obj: The data to serialize.
        :return: The serialized form of data.
        """
        if obj is None:
            return None
        elif isinstance(obj, self.PRIMITIVE_TYPES):
            return obj
        elif isinstance(obj, list):
            return [self.sanitize_for_serialization(sub_obj)
                    for sub_obj in obj]
        elif isinstance(obj, tuple):
            return tuple(self.sanitize_for_serialization(sub_obj)
                         for sub_obj in obj)
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()

        if isinstance(obj, dict):
            obj_dict = obj
        else:
            # Convert model obj to dict except
            # attributes `swagger_types`, `attribute_map`
            # and attributes which value is not None.
            # Convert attribute name to json key in
            # model definition for request.
            obj_dict = {obj.attribute_map[attr]: getattr(obj, attr)
                        for attr, _ in iteritems(obj.swagger_types)
                        if getattr(obj, attr) is not None}

        return {key: self.sanitize_for_serialization(val)
                for key, val in iteritems(obj_dict)}

    def deserialize(self, response, response_type):
        """
        Deserializes response into an object.
        :param response: RESTResponse object to be deserialized.
        :param response_type: class literal for
            deserialized object, or string of class name.
        :return: deserialized object.
        """
        # handle file downloading
        # save response body into a tmp file and return the instance
        if response_type == "file":
            return self.__deserialize_file(response)

        # fetch data from response object
        try:
            data = json.loads(response.data)
        except ValueError:
            data = response.data

        return self.__deserialize(data, response_type)

    def __deserialize(self, data, klass):
        """
        Deserializes dict, list, str into an object.
        :param data: dict, list or str.
        :param klass: class literal, or string of class name.
        :return: object.
        """
        if data is None:
            return None

        if type(klass) == str:
            if klass.startswith('list['):
                sub_kls = re.match('list\[(.*)\]', klass).group(1)
                return [self.__deserialize(sub_data, sub_kls)
                        for sub_data in data]

            if klass.startswith('dict('):
                sub_kls = re.match('dict\(([^,]*), (.*)\)', klass).group(2)
                return {k: self.__deserialize(v, sub_kls)
                        for k, v in iteritems(data)}

            # convert str to class
            if klass in self.NATIVE_TYPES_MAPPING:
                klass = self.NATIVE_TYPES_MAPPING[klass]
            else:
                klass = getattr(models, klass)

        if klass in self.PRIMITIVE_TYPES:
            return self.__deserialize_primitive(data, klass)
        elif klass == object:
            return self.__deserialize_object(data)
        elif klass == date:
            return self.__deserialize_date(data)
        elif klass == datetime:
            return self.__deserialize_datatime(data)
        else:
            return self.__deserialize_model(data, klass)

