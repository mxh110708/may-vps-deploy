#nullable enable
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using May.VpsDeploy.Core;
using System.Text.Json.Nodes;
using global::Windows.Foundation;
using global::Windows.System;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private string nodeDragSession = "";
    private readonly List<(Grid Row, Border Line, NodeReorderHandle Handle)> nodeDropRows = new();
    private NodePointerDrag? nodePointerDrag;
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? nodeScrollTimer;
    private Canvas? nodeDragOverlay;
    private Border? nodeDragPreview;
    private sealed class NodePointerDrag(JsonObject selected, string session, int source, Point origin)
    {
        public JsonObject Scheme { get; } = selected;
        public string Session { get; } = session;
        public int Source { get; } = source;
        public Point Origin { get; } = origin;
        public Point Position { get; set; } = origin;
        public int Insertion { get; set; } = source;
        public bool Moved { get; set; }
        public bool DropAllowed { get; set; }
        public uint PointerId { get; set; }
        public double GrabY { get; set; }
    }
    // Routed pointer events and the explicit background gesture interface
    // share these handlers. The test interface never injects input.
    private sealed class NodeReorderHandle : UserControl
    {
        public Func<Point, uint, Func<bool>, bool>? Press;
        public Action<Point, uint>? Move;
        public Func<Point, uint, bool>? Release;
        public Action<uint>? Cancel;
        public Action<VirtualKey>? Key;
        public Func<PointerRoutedEventArgs, Point>? Position;
        public NodeReorderHandle()
        {
            ProtectedCursor = Microsoft.UI.Input.InputSystemCursor.Create(Microsoft.UI.Input.InputSystemCursorShape.Hand);
            AddHandler(PointerPressedEvent, new PointerEventHandler((_, args) =>
            {
                if (!args.GetCurrentPoint(this).Properties.IsLeftButtonPressed || Position == null) return;
                if (Press?.Invoke(Position(args), args.Pointer.PointerId, () => CapturePointer(args.Pointer)) != true) return;
                Focus(FocusState.Pointer); args.Handled = true;
            }), true);
            AddHandler(PointerMovedEvent, new PointerEventHandler((_, args) => { if (Position != null) Move?.Invoke(Position(args), args.Pointer.PointerId); }), true);
            AddHandler(PointerReleasedEvent, new PointerEventHandler((_, args) =>
            {
                if (Position == null) return;
                Release?.Invoke(Position(args), args.Pointer.PointerId); ReleasePointerCapture(args.Pointer);
            }), true);
            PointerCanceled += (_, args) => Cancel?.Invoke(args.Pointer.PointerId);
            PointerCaptureLost += (_, args) => Cancel?.Invoke(args.Pointer.PointerId);
            KeyDown += (_, args) => { if (args.Key is VirtualKey.Escape or VirtualKey.Up or VirtualKey.Down) { Key?.Invoke(args.Key); args.Handled = true; } };
        }
    }
    private static StackPanel NodeDescription(JsonNode node) => Column(Text(node.Text("name")), Text(node.Text("kind") == "landing" ? "落地 · 连接 " + node.Text("transit_group") : "入口 · " + node.Text("region_group"), 13, true));
    private UIElement ReorderableNodeRow(JsonObject selected, JsonArray nodes, int index, FrameworkElement actions)
    {
        var session = nodeDragSession; var node = nodes[index]!;
        var grip = Text("≡", 22, true); grip.HorizontalAlignment = HorizontalAlignment.Center; grip.VerticalAlignment = VerticalAlignment.Center;
        var handle = new NodeReorderHandle { Content = grip, Tag = "NodeDragHandle." + index, Width = 44, Height = 52, Background = Brush(Paint.Surface), VerticalAlignment = VerticalAlignment.Center, ManipulationMode = ManipulationModes.None, IsTabStop = true };
        AutomationProperties.SetName(handle, "拖动排序 " + node.Text("name")); ToolTipService.SetToolTip(handle, "按住拖动；上下方向键调整顺序，Esc 取消");
        handle.Position = args => shell.TransformToVisual(mainScroll).TransformPoint(args.GetCurrentPoint(shell).Position);
        handle.Press = (position, pointerId, capture) =>
        {
            if (nodePointerDrag != null) return false;
            if (!BeginNodeReorder(selected, session, index, position)) return false;
            nodePointerDrag!.PointerId = pointerId;
            if (!capture()) { CancelNodeReorder(); return false; }
            return true;
        };
        handle.Move = (position, pointerId) => { if (nodePointerDrag?.PointerId == pointerId) UpdateNodeReorder(position); };
        handle.Release = (position, pointerId) => { if (nodePointerDrag?.PointerId != pointerId) return false; UpdateNodeReorder(position); return FinishNodeReorder(); };
        handle.Cancel = pointerId => { if (nodePointerDrag?.PointerId == pointerId) CancelNodeReorder(); };
        handle.Key = key =>
        {
            CancelNodeReorder();
            if (key == VirtualKey.Escape || scheme != selected || session != nodeDragSession || taskCancellation != null || activeTestDialog != null || currentPage != "clients" || designerStep != 1) return;
            if ((key == VirtualKey.Up && index == 0) || (key == VirtualKey.Down && index == nodes.Count - 1)) return;
            if (ClientSchemes.MoveNode(selected, index, key == VirtualKey.Up ? index - 1 : index + 2)) RefreshNodeOrder();
        };
        var grid = new Grid { ColumnSpacing = 12, Padding = new Thickness(12, 14, 20, 14) };
        grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); grid.ColumnDefinitions.Add(new() { Width = new GridLength(32) }); grid.ColumnDefinitions.Add(new()); grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        grid.Children.Add(handle); var rank = Text((index + 1).ToString("D2"), 13, true); rank.VerticalAlignment = VerticalAlignment.Center; Grid.SetColumn(rank, 1); grid.Children.Add(rank);
        var description = NodeDescription(node); description.VerticalAlignment = VerticalAlignment.Center; Grid.SetColumn(description, 2); grid.Children.Add(description); Grid.SetColumn(actions, 3); grid.Children.Add(actions);
        var target = new Grid { Tag = "NodeDropTarget." + index }; target.Children.Add(grid);
        var line = new Border { Height = 3, Background = Brush(Paint.Accent), Visibility = Visibility.Collapsed, IsHitTestVisible = false, Margin = new Thickness(12, 0, 12, 0) }; target.Children.Add(line); nodeDropRows.Add((target, line, handle));
        return target;
    }
    private bool BeginNodeReorder(JsonObject selected, string session, int source, Point position)
    {
        CancelNodeReorder();
        if (taskCancellation != null || activeTestDialog != null || session != nodeDragSession || scheme != selected || currentPage != "clients" || designerStep != 1 || source < 0 || source >= nodeDropRows.Count) return false;
        var row = nodeDropRows[source].Row; var top = row.TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y;
        nodePointerDrag = new(selected, session, source, position) { GrabY = position.Y - top };
        nodeScrollTimer ??= DispatcherQueue.CreateTimer(); nodeScrollTimer.Interval = TimeSpan.FromMilliseconds(40);
        nodeScrollTimer.Tick -= ScrollNodeReorder; nodeScrollTimer.Tick += ScrollNodeReorder; nodeScrollTimer.Start(); return true;
    }
    private void ScrollNodeReorder(Microsoft.UI.Dispatching.DispatcherQueueTimer sender, object args)
    {
        if (nodePointerDrag is not { Moved: true } drag || mainScroll == null) return;
        var change = drag.Position.Y < 48 ? -18 : drag.Position.Y > mainScroll.ActualHeight - 48 ? 18 : 0;
        if (change == 0 || !drag.DropAllowed) return;
        mainScroll.ChangeView(null, Math.Clamp(mainScroll.VerticalOffset + change, 0, mainScroll.ScrollableHeight), null, true);
        shell.UpdateLayout(); UpdateNodeReorder(drag.Position);
    }
    private void ShowNodeDragPreview(NodePointerDrag drag)
    {
        if (nodeDragPreview != null) return;
        var row = nodeDropRows[drag.Source].Row;
        var content = new Grid { ColumnSpacing = 12, Padding = new Thickness(18, 14, 20, 14) };
        content.ColumnDefinitions.Add(new() { Width = new GridLength(44) }); content.ColumnDefinitions.Add(new() { Width = new GridLength(32) }); content.ColumnDefinitions.Add(new());
        content.Children.Add(Text("≡", 22, true)); var rank = Text((drag.Source + 1).ToString("D2"), 13, true); Grid.SetColumn(rank, 1); content.Children.Add(rank);
        var description = NodeDescription(drag.Scheme["Nodes"]!.AsArray()[drag.Source]!); Grid.SetColumn(description, 2); content.Children.Add(description);
        nodeDragPreview = new Border { Tag = "NodeDragPreview", Child = content, Width = row.ActualWidth, Height = row.ActualHeight, Background = Brush(Paint.Surface), BorderBrush = Brush(Paint.Accent), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Opacity = .95, IsHitTestVisible = false };
        nodeDragOverlay = new Canvas { IsHitTestVisible = false }; Grid.SetRowSpan(nodeDragOverlay, shell.RowDefinitions.Count); shell.Children.Add(nodeDragOverlay); nodeDragOverlay.Children.Add(nodeDragPreview);
        ApplyFont(nodeDragPreview); row.Opacity = .3;
    }
    private void UpdateNodeReorder(Point position)
    {
        if (nodePointerDrag is not { } drag) return;
        if (taskCancellation != null || scheme != drag.Scheme || nodeDragSession != drag.Session || activeTestDialog != null) { CancelNodeReorder(); return; }
        drag.Position = position; drag.Moved |= Math.Abs(position.Y - drag.Origin.Y) >= 5;
        foreach (var item in nodeDropRows) { item.Line.Visibility = Visibility.Collapsed; item.Row.Background = null; }
        if (!drag.Moved || mainScroll == null || nodeDropRows.Count == 0) return;
        ShowNodeDragPreview(drag);
        var viewport = mainScroll.TransformToVisual(nodeDragOverlay).TransformPoint(new(0, 0));
        var source = nodeDropRows[drag.Source].Row.TransformToVisual(mainScroll).TransformPoint(new(0, 0));
        nodeDragOverlay!.Clip = new RectangleGeometry { Rect = new Rect(viewport.X, viewport.Y, mainScroll.ActualWidth, mainScroll.ActualHeight) };
        Canvas.SetLeft(nodeDragPreview!, viewport.X + source.X); Canvas.SetTop(nodeDragPreview!, viewport.Y + position.Y - drag.GrabY);
        drag.DropAllowed = position.X >= source.X && position.X <= source.X + nodeDropRows[drag.Source].Row.ActualWidth && position.Y >= 0 && position.Y <= mainScroll.ActualHeight;
        if (!drag.DropAllowed) return;
        // Choose the slot nearest the centre of the visible dragged row.
        // Using the pointer makes the threshold depend on where the grip was
        // pressed and requires moving past an entire neighbour to swap it.
        var centre = position.Y - drag.GrabY + nodeDropRows[drag.Source].Row.ActualHeight / 2;
        var nearest = drag.Source;
        var distance = Math.Abs(centre - (source.Y + nodeDropRows[drag.Source].Row.ActualHeight / 2));
        for (var index = 0; index < nodeDropRows.Count; index++)
        {
            var row = nodeDropRows[index].Row; var top = row.TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y;
            var candidate = Math.Abs(centre - (top + row.ActualHeight / 2));
            if (candidate < distance - .01) { nearest = index; distance = candidate; }
        }
        var insertion = nearest > drag.Source ? nearest + 1 : nearest;
        drag.Insertion = insertion;
        if (insertion == drag.Source || insertion == drag.Source + 1) return;
        var target = nodeDropRows[Math.Min(insertion, nodeDropRows.Count - 1)]; target.Row.Background = Brush(Paint.InputHover); target.Line.VerticalAlignment = insertion == nodeDropRows.Count ? VerticalAlignment.Bottom : VerticalAlignment.Top; target.Line.Visibility = Visibility.Visible;
    }
    private void RefreshNodeOrder()
    {
        var offset = mainScroll!.VerticalOffset; Navigate("clients"); shell.UpdateLayout(); mainScroll!.ChangeView(null, offset, null, true);
    }
    private bool FinishNodeReorder()
    {
        var drag = nodePointerDrag; CancelNodeReorder();
        if (drag == null || !drag.Moved || !drag.DropAllowed || taskCancellation != null || scheme != drag.Scheme || nodeDragSession != drag.Session) return false;
        if (!ClientSchemes.MoveNode(drag.Scheme, drag.Source, drag.Insertion)) return false;
        RefreshNodeOrder(); return true;
    }
    private void CancelNodeReorder()
    {
        var drag = nodePointerDrag; nodePointerDrag = null; nodeScrollTimer?.Stop();
        if (nodeDragOverlay != null) shell.Children.Remove(nodeDragOverlay); nodeDragOverlay = null; nodeDragPreview = null;
        foreach (var item in nodeDropRows) { item.Line.Visibility = Visibility.Collapsed; item.Row.Background = null; item.Row.Opacity = 1; }
        if (drag != null && drag.Source < nodeDropRows.Count) nodeDropRows[drag.Source].Handle.ReleasePointerCaptures();
    }
}
