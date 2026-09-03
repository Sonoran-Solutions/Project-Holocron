using DotRecast.Core.Numerics;
using Holocron.Common.Navigation;
using Holocron.World.Navigation;
using Xunit;

namespace Holocron.Tests;

public class NavMeshTests
{
    [Fact]
    public void NavMesh_CreatesGrid_AndFindsSmoothPath()
    {
        var navMesh = NavMeshService.CreatePlane(-50.0f, -50.0f, 50.0f, 50.0f, y: 0.0f);

        var start = new RcVec3f(-20.0f, 0.0f, -20.0f);
        var end = new RcVec3f(20.0f, 0.0f, 20.0f);

        bool pathFound = navMesh.FindPath(start, end, out var waypoints);

        Assert.True(pathFound);
        Assert.NotEmpty(waypoints);
        Assert.True(waypoints.Count >= 2);

        var first = waypoints.First();
        var last = waypoints.Last();
        Assert.InRange(first.X, -22.0f, -18.0f);
        Assert.InRange(last.X, 18.0f, 22.0f);
    }

    [Fact]
    public void NavMesh_HasLineOfSight_ReturnsTrueForOpenSpace()
    {
        var navMesh = NavMeshService.CreatePlane(-30.0f, -30.0f, 30.0f, 30.0f, y: 0.0f);

        var start = new RcVec3f(-5.0f, 0.0f, 0.0f);
        var end = new RcVec3f(15.0f, 0.0f, 0.0f);

        bool clearLos = navMesh.HasLineOfSight(start, end, out var hitPos);

        Assert.True(clearLos);
    }

    [Fact]
    public void MovementGenerator_FollowsLeader_MaintainsFormation()
    {
        var navMesh = NavMeshService.CreatePlane(-50.0f, -50.0f, 50.0f, 50.0f, y: 0.0f);
        var mover = new MovementGenerator { Speed = 10.0f };

        var botPos = new RcVec3f(-15.0f, 0.0f, 0.0f);
        var leaderPos = new RcVec3f(0.0f, 0.0f, 0.0f);

        mover.Follow(navMesh, botPos, leaderPos, followDistance: 3.0f);

        Assert.True(mover.HasPath);
        Assert.Equal(MovementType.Follow, mover.Type);

        // Advance 1 second (10m step)
        botPos = mover.Update(botPos, deltaSeconds: 1.0f);

        // Bot should have moved closer to leader (-15m -> -5m, so distance to leader at 0 is ~5m)
        float dist = (float)Math.Sqrt(botPos.X * botPos.X + botPos.Z * botPos.Z);
        Assert.True(dist < 10.0f);
    }

    [Fact]
    public void MovementGenerator_FleesFromHazard_FindsSafeCoordinates()
    {
        var navMesh = NavMeshService.CreatePlane(-50.0f, -50.0f, 50.0f, 50.0f, y: 0.0f);
        var mover = new MovementGenerator { Speed = 12.0f };

        var botPos = new RcVec3f(1.0f, 0.0f, 1.0f);
        var hazardCenter = new RcVec3f(0.0f, 0.0f, 0.0f);
        float hazardRadius = 8.0f;

        mover.FleeFromHazard(navMesh, botPos, hazardCenter, hazardRadius);

        Assert.True(mover.HasPath);
        Assert.Equal(MovementType.Flee, mover.Type);

        var destination = mover.Waypoints.Last();
        float distFromHazard = (float)Math.Sqrt(destination.X * destination.X + destination.Z * destination.Z);

        // Escape point must be safely outside hazard radius (> 8m)
        Assert.True(distFromHazard > hazardRadius);
    }
}
