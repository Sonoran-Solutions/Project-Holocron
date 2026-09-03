using DotRecast.Core.Numerics;
using DotRecast.Detour;
using DotRecast.Recast;
using DotRecast.Recast.Geom;

namespace Holocron.Common.Navigation;

/// <summary>
/// Server-side navigation mesh and pathfinding service wrapping DotRecast (Detour/Recast).
/// Provides 3D waypoint navigation, line-of-sight raycasting, and dynamic spatial queries.
/// </summary>
public sealed class NavMeshService
{
    private readonly DtNavMesh _navMesh;
    private readonly DtNavMeshQuery _query;
    private readonly IDtQueryFilter _filter;
    private static readonly RcVec3f DefaultExtents = new(5.0f, 5.0f, 5.0f);

    public DtNavMesh NavMesh => _navMesh;
    public DtNavMeshQuery Query => _query;

    public NavMeshService(DtNavMesh navMesh)
    {
        _navMesh = navMesh ?? throw new ArgumentNullException(nameof(navMesh));
        _query = new DtNavMeshQuery(_navMesh);
        _filter = new DtQueryDefaultFilter();
    }

    /// <summary>
    /// Creates a NavMeshService by building a navigation mesh from raw 3D mesh vertices and triangle indices.
    /// </summary>
    public static NavMeshService CreateFromGeometry(float[] vertices, int[] triangles, float cellSize = 0.5f, float cellHeight = 0.2f, float agentHeight = 2.0f, float agentRadius = 0.6f)
    {
        var geom = new RcSampleInputGeomProvider(vertices, triangles);
        var config = new RcConfig(
            partitionType: RcPartition.WATERSHED,
            cellSize: cellSize,
            cellHeight: cellHeight,
            agentMaxSlope: 45.0f,
            agentHeight: agentHeight,
            agentRadius: agentRadius,
            agentMaxClimb: 0.9f,
            regionMinSize: 8,
            regionMergeSize: 20,
            edgeMaxLen: 12.0f,
            edgeMaxError: 1.3f,
            vertsPerPoly: 6,
            detailSampleDist: 6.0f,
            detailSampleMaxError: 1.0f,
            filterLowHangingObstacles: false,
            filterLedgeSpans: false,
            filterWalkableLowHeightSpans: false,
            walkableAreaMod: new RcAreaModification(1),
            buildMeshDetail: true
        );

        var bmin = geom.GetMeshBoundsMin();
        var bmax = geom.GetMeshBoundsMax();

        // Ensure vertical bounds provide sufficient vertical clearance for the agent to stand
        var expandedBmin = new RcVec3f(bmin.X, bmin.Y - 2.0f, bmin.Z);
        var expandedBmax = new RcVec3f(bmax.X, Math.Max(bmax.Y + agentHeight + 6.0f, bmin.Y + 10.0f), bmax.Z);

        var builderCfg = new RcBuilderConfig(config, expandedBmin, expandedBmax);
        var builder = new RcBuilder();
        var builderResult = builder.Build(geom, builderCfg, false);

        if (builderResult.Mesh == null || builderResult.MeshDetail == null || builderResult.Mesh.npolys == 0)
        {
            throw new InvalidOperationException("Failed to generate poly mesh from input geometry.");
        }

        // Set walkable flag (1) on all generated navigation polygons
        for (int i = 0; i < builderResult.Mesh.npolys; i++)
        {
            builderResult.Mesh.flags[i] = 1;
        }

        var navMeshCreateParams = new DtNavMeshCreateParams
        {
            verts = builderResult.Mesh.verts,
            vertCount = builderResult.Mesh.nverts,
            polys = builderResult.Mesh.polys,
            polyAreas = builderResult.Mesh.areas,
            polyFlags = builderResult.Mesh.flags,
            polyCount = builderResult.Mesh.npolys,
            nvp = builderResult.Mesh.nvp,
            detailMeshes = builderResult.MeshDetail.meshes,
            detailVerts = builderResult.MeshDetail.verts,
            detailVertsCount = builderResult.MeshDetail.nverts,
            detailTris = builderResult.MeshDetail.tris,
            detailTriCount = builderResult.MeshDetail.ntris,
            walkableHeight = agentHeight,
            walkableRadius = agentRadius,
            walkableClimb = 0.9f,
            bmin = expandedBmin,
            bmax = expandedBmax,
            cs = cellSize,
            ch = cellHeight,
            buildBvTree = true
        };

        var meshData = DtNavMeshBuilder.CreateNavMeshData(navMeshCreateParams);
        if (meshData == null)
        {
            throw new InvalidOperationException("Failed to create Detour navmesh data.");
        }

        var navMesh = new DtNavMesh();
        navMesh.Init(meshData, 2048, 1);
        return new NavMeshService(navMesh);
    }

    /// <summary>
    /// Creates a planar NavMesh grid covering [minX, minZ] to [maxX, maxZ] at given height Y.
    /// Useful for starting zones, arena floors, and flashpoint encounters.
    /// </summary>
    public static NavMeshService CreatePlane(float minX, float minZ, float maxX, float maxZ, float y = 0.0f)
    {
        float[] vertices = new float[]
        {
            minX, y, minZ,
            maxX, y, minZ,
            maxX, y, maxZ,
            minX, y, maxZ
        };

        // Counter-clockwise upward normal winding
        int[] triangles = new int[]
        {
            0, 2, 1,
            0, 3, 2
        };

        return CreateFromGeometry(vertices, triangles);
    }

    /// <summary>
    /// Calculates a smooth straight path of 3D waypoints between start and end coordinates.
    /// </summary>
    public bool FindPath(RcVec3f start, RcVec3f end, out List<RcVec3f> waypoints)
    {
        waypoints = new List<RcVec3f>();

        _query.FindNearestPoly(start, DefaultExtents, _filter, out long startRef, out RcVec3f startPt, out _);
        _query.FindNearestPoly(end, DefaultExtents, _filter, out long endRef, out RcVec3f endPt, out _);

        if (startRef == 0 || endRef == 0)
            return false;

        Span<long> path = stackalloc long[64];
        var status = _query.FindPath(startRef, endRef, startPt, endPt, _filter, path, out int pathCount, 64);
        if (!status.Succeeded() || pathCount == 0)
            return false;

        Span<DtStraightPath> straightPath = stackalloc DtStraightPath[64];
        var straightPathStatus = _query.FindStraightPath(startPt, endPt, path, pathCount, straightPath, out int straightPathCount, 64, 0);
        if (!straightPathStatus.Succeeded() || straightPathCount == 0)
            return false;

        for (int i = 0; i < straightPathCount; i++)
        {
            waypoints.Add(straightPath[i].pos);
        }

        return waypoints.Count > 0;
    }

    /// <summary>
    /// Line-of-sight raycast against navigation mesh walls and collision boundaries.
    /// Returns true if LOS is clear (no wall hit), or false if blocked.
    /// </summary>
    public bool HasLineOfSight(RcVec3f start, RcVec3f end, out RcVec3f hitPosition)
    {
        hitPosition = end;

        _query.FindNearestPoly(start, DefaultExtents, _filter, out long startRef, out RcVec3f startPt, out _);
        if (startRef == 0) return false;

        DtRaycastHit hit = default;
        var status = _query.Raycast(startRef, startPt, end, _filter, 0, ref hit, 0);
        if (!status.Succeeded())
            return false;

        if (hit.t < 1.0f)
        {
            // Raycast hit an obstacle / wall
            hitPosition = new RcVec3f(
                startPt.X + (end.X - startPt.X) * hit.t,
                startPt.Y + (end.Y - startPt.Y) * hit.t,
                startPt.Z + (end.Z - startPt.Z) * hit.t
            );
            return false; // Line of sight blocked
        }

        return true; // Clear line of sight
    }

    /// <summary>
    /// Finds a valid escape point on the navmesh away from a hazard center (e.g. boss AoE circle).
    /// </summary>
    public bool FindEscapePoint(RcVec3f currentPos, RcVec3f hazardCenter, float hazardRadius, out RcVec3f escapePoint)
    {
        escapePoint = currentPos;

        // Calculate direction vector away from hazard
        float dx = currentPos.X - hazardCenter.X;
        float dz = currentPos.Z - hazardCenter.Z;
        float dist = (float)Math.Sqrt(dx * dx + dz * dz);

        if (dist < 0.001f)
        {
            dx = 1.0f;
            dz = 0.0f;
            dist = 1.0f;
        }

        // Project outside the hazard radius with 2.5m safety margin
        float targetDistance = hazardRadius + 2.5f;
        RcVec3f target = new(
            hazardCenter.X + (dx / dist) * targetDistance,
            currentPos.Y,
            hazardCenter.Z + (dz / dist) * targetDistance
        );

        _query.FindNearestPoly(target, DefaultExtents, _filter, out long polyRef, out RcVec3f nearest, out _);
        if (polyRef != 0)
        {
            escapePoint = nearest;
            return true;
        }

        return false;
    }
}
