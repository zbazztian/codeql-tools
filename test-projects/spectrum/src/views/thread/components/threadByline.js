// @flow
import * as React from 'react';
import Badge from 'src/components/badges';
import type { ThreadParticipantType } from 'shared/graphql/fragments/thread/threadParticipant';
import { UserAvatar } from 'src/components/avatar';
import {
  Byline,
  BylineMeta,
  AuthorName,
  AuthorNameLink,
  AuthorNameNoLink,
  AuthorUsername,
} from '../style';

type Props = {
  author: {
    ...$Exact<ThreadParticipantType>,
  },
};
class ThreadByline extends React.Component<Props> {
  render() {
    const { author } = this.props;
    const { user, roles } = author;

    return (
      <Byline>
        <UserAvatar user={user} size={40} showHoverProfile={false} />
        <BylineMeta>
          {user.username ? (
            <AuthorNameLink to={`/users/${user.username}`}>
              <AuthorName>{user.name}</AuthorName>
              <AuthorUsername>@{user.username}</AuthorUsername>
              {roles.map((role, index) => (
                <Badge type={role} key={index} />
              ))}
              {user.betaSupporter && (
                <Badge type="beta-supporter" label="Supporter" />
              )}
            </AuthorNameLink>
          ) : (
            <AuthorNameNoLink>
              <AuthorName>{user.name}</AuthorName>
              {roles.map((role, index) => (
                <Badge type={role} key={index} />
              ))}
            </AuthorNameNoLink>
          )}
        </BylineMeta>
      </Byline>
    );
  }
}

export default ThreadByline;
