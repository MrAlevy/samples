import gql from 'graphql-tag'
import { Context } from '../types'
import { ForbiddenError } from 'apollo-server-express'
const { SchemaDirectiveVisitor } = require('graphql-tools')
import accessChecker from '../utils/accessChecker'
import { ACCESS_GROUP } from '../constants'

const typeDefs = gql`
  directive @accessControl(allowedGroups: [AllowedGroups]!) on FIELD_DEFINITION
  directive @accessRights(
    allowRead: [AllowedGroups]
    allowWrite: [AllowedGroups]
  ) on FIELD_DEFINITION

  enum AllowedGroups {
    GENERAL
    GENERAL_EXC_ME
    ME
    TECH_PORTAL
    HR_RU
    WIKI_EDITORS
    HR_EDITORS
    HR_ADMINS
    REVIEWERS
    DEVELOPMENT_PLAN_REVIEWERS
    MATRICES_REVIEWERS
    FEEDBACK
    WORKSPACE_PLANNER
    SYS_ADMINS
    SUPER_USER
    LIBRARIAN
    AAD_CREATORS
    AAD_USER_EDITORS
    AAD_GROUP_EDITORS
    AGILE_MANAGERS
  }

  type Access {
    read: Boolean
    write: Boolean
  }

  input UpdateAccessGroupInput {
    name: String
    members: [String]
  }

  extend type Query {
    isAuthenticated: Boolean
    getMembersOf(group: String): [Employee!]
      @accessControl(allowedGroups: [SUPER_USER])
  }

  extend type Mutation {
    updateAccessGroup(input: UpdateAccessGroupInput): String
      @accessControl(allowedGroups: [SUPER_USER])
  }
`

type UpdateAccessGroupArgs = {
  input: {
    name: string
    members?: string[]
  }
}

/**
 * Checks user existing in the specified access groups and denies access if has not found
 */
class CheckAccessControl extends SchemaDirectiveVisitor {
  visitFieldDefinition(field: any) {
    this.ensureFieldWrapped(field)
  }

  ensureFieldWrapped(field: any) {
    const { resolve } = field

    field.resolve = async (...args: [any, any, Context]) => {
      const parallelList = []
      for (const group of this.args.allowedGroups) {
        parallelList.push(accessChecker(group, args))
      }
      const resList = await Promise.all(parallelList)

      if (resList.includes(true)) return resolve.apply(this, args)
      throw new ForbiddenError('You have got no access')
    }
  }
}

/**
 * Checks user existing in the specified access groups and injects additional args to query:
 * accessRights: {read: boolean, write: boolean}
 */

class GetAccessRights extends SchemaDirectiveVisitor {
  visitFieldDefinition(field: any) {
    this.ensureFieldWrapped(field)
  }

  ensureFieldWrapped(field: any) {
    const { resolve } = field

    field.resolve = async (...args: [any, any, Context]) => {
      let { allowRead, allowWrite } = this.args

      if (!allowRead) allowRead = []
      if (!allowWrite) allowWrite = []

      const unionAllowGroups = new Set([...allowRead, ...allowWrite])

      // Add additional argument to query
      args[1].accessRights = { read: false, write: false }

      // Function for rewriting access rights as additional argument to query
      const setAccess = (group: string) => {
        if (allowRead.includes(group)) args[1].accessRights.read = true
        if (allowWrite.includes(group)) args[1].accessRights.write = true
      }

      const parallelList = []
      for (const group of unionAllowGroups) {
        parallelList.push(accessChecker(group, args))
      }
      const resList = await Promise.all(parallelList)
      resList.forEach((bool, i) =>
        bool ? setAccess(Array.from(unionAllowGroups)[i]) : null
      )

      return resolve.apply(this, args)
    }
  }
}

const resolvers = {
  Query: {
    isAuthenticated: () => true,
    getMembersOf: async (
      _: never,
      args: { group: keyof typeof ACCESS_GROUP },
      context: Context
    ) => {
      const group = await context.dataSources.strapiAPI
        ._accessGroup()
        .getSingle({ name: args.group })
      return group?.members
    },
  },
  Mutation: {
    updateAccessGroup: async (
      _: never,
      { input }: UpdateAccessGroupArgs,
      context: Context
    ) => {
      const query = context.dataSources.strapiAPI._accessGroup()
      if (input.members) {
        const [group] = await query.getMany({ name: input.name })
        await query.update({
          id: group.id,
          members: input.members,
        })
        return input.name
      }
    },
  },
}

const directives = {
  accessControl: CheckAccessControl,
  accessRights: GetAccessRights,
}

module.exports = {
  typeDefs,
  resolvers,
  directives,
}
