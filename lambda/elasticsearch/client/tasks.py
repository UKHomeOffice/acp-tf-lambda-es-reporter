#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

from .utils import NamespacedClient, query_params, _make_path


class TasksClient(NamespacedClient):
    @query_params(
        "actions",
        "detailed",
        "group_by",
        "nodes",
        "parent_task_id",
        "wait_for_completion",
        "timeout",
    )
    def list(self, params=None):
        """
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/tasks.html>`_

        :arg actions: A comma-separated list of actions that should be returned.
            Leave empty to return all.
        :arg detailed: Return detailed task information (default: false)
        :arg group_by: Group tasks by nodes or parent/child relationships,
            default 'nodes', valid choices are: 'nodes', 'parents'
        :arg nodes: A comma-separated list of node IDs or names to limit the
            returned information; use `_local` to return information from the
            node you're connecting to, leave empty to get information from all
            nodes
        :arg parent_task_id: Return tasks with specified parent task id
            (node_id:task_number). Set to -1 to return all.
        :arg wait_for_completion: Wait for the matching tasks to complete
            (default: false)
        :arg timeout: Maximum waiting time for `wait_for_completion`
        """
        return self.transport.perform_request("GET", "/_tasks", params=params)

    @query_params("actions", "nodes", "parent_task_id")
    def cancel(self, task_id=None, params=None):
        """

        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/tasks.html>`_

        :arg task_id: Cancel the task with specified task id
            (node_id:task_number)
        :arg actions: A comma-separated list of actions that should be
            cancelled. Leave empty to cancel all.
        :arg nodes: A comma-separated list of node IDs or names to limit the
            returned information; use `_local` to return information from the
            node you're connecting to, leave empty to get information from all
            nodes
        :arg parent_task_id: Cancel tasks with specified parent task id
            (node_id:task_number). Set to -1 to cancel all.
        """
        return self.transport.perform_request(
            "POST", _make_path("_tasks", task_id, "_cancel"), params=params
        )

    @query_params("wait_for_completion", "timeout")
    def get(self, task_id=None, params=None):
        """
        Retrieve information for a particular task.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/tasks.html>`_

        :arg task_id: Return the task with specified id (node_id:task_number)
        :arg wait_for_completion: Wait for the matching tasks to complete
            (default: false)
        :arg timeout: Maximum waiting time for `wait_for_completion`
        """
        return self.transport.perform_request(
            "GET", _make_path("_tasks", task_id), params=params
        )
