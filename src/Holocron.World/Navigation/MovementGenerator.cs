using DotRecast.Core.Numerics;
using Holocron.Common.Navigation;

namespace Holocron.World.Navigation;

public enum MovementType
{
    Idle,
    Point,
    Follow,
    Chase,
    Flee
}

/// <summary>
/// Controls entity locomotion across server ticks following navigation mesh paths.
/// </summary>
public sealed class MovementGenerator
{
    private readonly List<RcVec3f> _waypoints = new();
    private int _currentWaypointIndex;

    public MovementType Type { get; private set; } = MovementType.Idle;
    public float Speed { get; set; } = 7.0f; // 7 m/s run speed
    public bool HasPath => _waypoints.Count > 0 && _currentWaypointIndex < _waypoints.Count;
    public IReadOnlyList<RcVec3f> Waypoints => _waypoints;

    public void MoveTo(NavMeshService navMesh, RcVec3f start, RcVec3f target)
    {
        if (navMesh.FindPath(start, target, out var path))
        {
            _waypoints.Clear();
            _waypoints.AddRange(path);
            _currentWaypointIndex = 0;
            Type = MovementType.Point;
        }
    }

    public void Follow(NavMeshService navMesh, RcVec3f start, RcVec3f leaderPos, float followDistance = 3.0f)
    {
        float dx = start.X - leaderPos.X;
        float dz = start.Z - leaderPos.Z;
        float dist = (float)Math.Sqrt(dx * dx + dz * dz);

        if (dist > followDistance + 1.5f)
        {
            RcVec3f dest = new(
                leaderPos.X + (dist > 0.1f ? (dx / dist) * followDistance : followDistance),
                leaderPos.Y,
                leaderPos.Z + (dist > 0.1f ? (dz / dist) * followDistance : 0)
            );

            if (navMesh.FindPath(start, dest, out var path))
            {
                _waypoints.Clear();
                _waypoints.AddRange(path);
                _currentWaypointIndex = 0;
                Type = MovementType.Follow;
            }
        }
        else if (dist <= followDistance)
        {
            Stop();
        }
    }

    public void FleeFromHazard(NavMeshService navMesh, RcVec3f currentPos, RcVec3f hazardCenter, float hazardRadius)
    {
        if (navMesh.FindEscapePoint(currentPos, hazardCenter, hazardRadius, out var escapePoint))
        {
            MoveTo(navMesh, currentPos, escapePoint);
            Type = MovementType.Flee;
        }
    }

    public RcVec3f Update(RcVec3f currentPos, float deltaSeconds)
    {
        float remainingDistance = Speed * deltaSeconds;

        while (remainingDistance > 0 && HasPath)
        {
            var targetPoint = _waypoints[_currentWaypointIndex];
            float dx = targetPoint.X - currentPos.X;
            float dy = targetPoint.Y - currentPos.Y;
            float dz = targetPoint.Z - currentPos.Z;
            float distanceToWaypoint = (float)Math.Sqrt(dx * dx + dy * dy + dz * dz);

            if (distanceToWaypoint <= remainingDistance)
            {
                currentPos = targetPoint;
                remainingDistance -= distanceToWaypoint;
                _currentWaypointIndex++;
                if (_currentWaypointIndex >= _waypoints.Count)
                {
                    Stop();
                    break;
                }
            }
            else
            {
                float ratio = remainingDistance / distanceToWaypoint;
                currentPos = new RcVec3f(
                    currentPos.X + dx * ratio,
                    currentPos.Y + dy * ratio,
                    currentPos.Z + dz * ratio
                );
                remainingDistance = 0;
            }
        }

        return currentPos;
    }

    public void Stop()
    {
        _waypoints.Clear();
        _currentWaypointIndex = 0;
        Type = MovementType.Idle;
    }
}
