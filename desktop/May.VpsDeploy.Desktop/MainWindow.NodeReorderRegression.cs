#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using May.VpsDeploy.Core;
using global::Windows.Foundation;
using global::Windows.System;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task NodeReorderRegression(string output, string theme, Action<bool, string> require)
    {
        var originalSize = AppWindow.Size;
        var scale = shell.XamlRoot.RasterizationScale;
        try
        {
            AppWindow.Resize(new((int)(1000 * scale), (int)(720 * scale)));
            Navigate("clients"); await Task.Delay(120); shell.UpdateLayout();
            require(nodeDropRows.Count == 3 && Find<NodeReorderHandle>(page).Count() == 3, "节点指针拖动手柄未接上。");
            Point Grip(int index) => nodeDropRows[index].Handle.TransformToVisual(mainScroll).TransformPoint(new(22, 26));
            Point Before(int index) => new(Grip(index).X, nodeDropRows[index].Row.TransformToVisual(mainScroll).TransformPoint(new(0, 2)).Y);
            async Task WaitForState(Func<bool> condition, string reason)
            {
                var until = DateTimeOffset.UtcNow.AddSeconds(3);
                while (!condition() && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(25); }
                require(condition(), reason);
            }
            await WaitForState(() => nodeDropRows.All(row => row.Handle.IsLoaded && row.Row.ActualHeight > 0), "节点手柄布局未就绪。");
            // A compact desktop can clip the third row. Scroll the real viewport
            // before checking hit testing or starting a pointer gesture.
            var initialOffset = Math.Clamp(mainScroll!.VerticalOffset + Before(0).Y - 14, 0, mainScroll.ScrollableHeight);
            mainScroll.ChangeView(null, initialOffset, null, true);
            await WaitForState(() => Math.Abs(mainScroll.VerticalOffset - initialOffset) < 1 && Before(0).Y >= 0 && Grip(2).Y < mainScroll.ActualHeight - 12, "拖动起点与落点没有进入实际可视区域。");
            // Scroll offset, transforms and the compositor do not settle in the
            // same dispatcher turn. Measure drag geometry after presentation.
            await Task.Delay(100); shell.UpdateLayout();
            // Reproduce adjacent swaps at the halfway boundary between slots,
            // including both ends of the grip. Use actual rendered geometry.
            var adjacentRow = nodeDropRows[1].Row;
            var adjacentGrip = nodeDropRows[1].Handle;
            var adjacentOrigin = adjacentGrip.TransformToVisual(mainScroll).TransformPoint(new(22, 50));
            var adjacentTop = adjacentRow.TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y;
            var neighbour = nodeDropRows[0].Row;
            var neighbourCentre = neighbour.TransformToVisual(mainScroll).TransformPoint(new(0, neighbour.ActualHeight / 2)).Y;
            var boundary = (neighbourCentre + adjacentTop + adjacentRow.ActualHeight / 2) / 2;
            var adjacentTarget = new Point(adjacentOrigin.X, boundary - 4 + adjacentOrigin.Y - adjacentTop - adjacentRow.ActualHeight / 2);
            require(adjacentGrip.Press?.Invoke(adjacentOrigin, 1, () => true) == true, "相邻交换按下未开始。");
            adjacentGrip.Move?.Invoke(adjacentTarget, 1); shell.UpdateLayout();
            var renderedTop = nodeDragPreview!.TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y;
            require(Math.Abs(renderedTop - (adjacentTarget.Y - (adjacentOrigin.Y - adjacentTop))) < 1, "预览实际位置与指针偏移不一致：" + renderedTop.ToString("F1"));
            require(nodePointerDrag?.Insertion == 0 && nodeDropRows[0].Line.Visibility == Visibility.Visible, "预览已越过相邻交换位置，仍要求额外上拖才能交换。");
            await Task.Delay(60); // Let the compositor present the moved preview.
            var previewGeometry = new JsonObject { ["scroll_offset"] = mainScroll!.VerticalOffset, ["grab"] = nodePointerDrag!.GrabY, ["pointer"] = adjacentTarget.Y, ["boundary"] = boundary, ["row_height"] = adjacentRow.ActualHeight, ["preview_top_scroll"] = renderedTop, ["preview_top_shell"] = nodeDragPreview.TransformToVisual(shell).TransformPoint(new(0, 0)).Y, ["neighbour_centre_shell"] = neighbour.TransformToVisual(shell).TransformPoint(new(0, neighbour.ActualHeight / 2)).Y, ["source_centre_shell"] = adjacentRow.TransformToVisual(shell).TransformPoint(new(0, adjacentRow.ActualHeight / 2)).Y, ["canvas_top"] = Canvas.GetTop(nodeDragPreview), ["viewport_top_shell"] = mainScroll.TransformToVisual(shell).TransformPoint(new(0, 0)).Y, ["overlay_top_shell"] = nodeDragOverlay!.TransformToVisual(shell).TransformPoint(new(0, 0)).Y };
            ArchiveStore.WriteJson(SafePath.Resolve(output, "node-adjacent-geometry-" + theme.ToLowerInvariant() + ".json"), previewGeometry);
            await Capture(SafePath.Resolve(output, "node-adjacent-" + theme.ToLowerInvariant() + ".png"));
            CancelNodeReorder();
            foreach (var gripY in new[] { 2.0, 26.0, 50.0 })
            {
                foreach (var sourceIndex in new[] { 1, 0 })
                {
                    var otherIndex = 1 - sourceIndex;
                    var row = nodeDropRows[sourceIndex].Row; var other = nodeDropRows[otherIndex].Row;
                    var gripHandle = nodeDropRows[sourceIndex].Handle;
                    var originPoint = gripHandle.TransformToVisual(mainScroll).TransformPoint(new(22, gripY));
                    var rowTop = row.TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y;
                    var rowCentre = rowTop + row.ActualHeight / 2;
                    var otherCentre = other.TransformToVisual(mainScroll).TransformPoint(new(0, other.ActualHeight / 2)).Y;
                    var midpoint = (rowCentre + otherCentre) / 2;
                    var direction = sourceIndex == 1 ? -1 : 1;
                    Point At(double offset) => new(originPoint.X, midpoint + offset + originPoint.Y - rowTop - row.ActualHeight / 2);
                    var expectedNames = scheme!["Nodes"]!.AsArray().Select(n => n!.Text("name")).ToArray();
                    (expectedNames[0], expectedNames[1]) = (expectedNames[1], expectedNames[0]);
                    var candidate = new JsonObject { ["ValidationStatus"] = "Passed" }; scheme["Candidate"] = candidate;
                    require(gripHandle.Press?.Invoke(originPoint, 1, () => true) == true, "临界相邻交换未开始。");
                    gripHandle.Move?.Invoke(At(-direction * 3), 1); shell.UpdateLayout();
                    require(nodePointerDrag!.Insertion is var same && (same == sourceIndex || same == sourceIndex + 1) && nodeDropRows.All(item => item.Line.Visibility == Visibility.Collapsed), "未越过交换位置就改变落点。");
                    gripHandle.Move?.Invoke(At(0), 1); shell.UpdateLayout();
                    require(nodeDropRows.All(item => item.Line.Visibility == Visibility.Collapsed), "恰好位于交换边界时没有保留原位置。");
                    gripHandle.Move?.Invoke(At(direction * 3), 1); shell.UpdateLayout();
                    var previewCentre = nodeDragPreview!.TransformToVisual(mainScroll).TransformPoint(new(0, row.ActualHeight / 2)).Y;
                    require(Math.Abs(previewCentre - midpoint - direction * 3) < 1 && nodeDropRows.Any(item => item.Line.Visibility == Visibility.Visible), "普通拖动的实际预览与交换提示不一致：" + sourceIndex + "/" + gripY + "，预览 " + previewCentre.ToString("F1") + "，临界 " + midpoint.ToString("F1") + "，允许 " + nodePointerDrag!.DropAllowed);
                    var adjacentOffset = mainScroll!.VerticalOffset;
                    require(gripHandle.Release?.Invoke(At(direction * 3), 1) == true && scheme["Candidate"] == null && scheme["Nodes"]!.AsArray().Select(n => n!.Text("name")).SequenceEqual(expectedNames), "相邻交换释放未保存顺序或失效候选。");
                    await WaitForState(() => nodeDropRows.All(item => item.Handle.IsLoaded && item.Row.ActualHeight > 0) && Math.Abs(mainScroll.VerticalOffset - adjacentOffset) < 1 && Before(0).Y >= 0 && Grip(2).Y < mainScroll.ActualHeight - 12, "相邻交换后控件或滚动位置未就绪。");
                }
            }
            string Names() => string.Join("|", scheme!["Nodes"]!.AsArray().Select(n => n!.Text("name")));
            bool Press(int index, uint id = 1, bool capture = true) => nodeDropRows[index].Handle.Press?.Invoke(Grip(index), id, () => capture) == true;
            var handle = nodeDropRows[2].Handle;
            // Scroll transforms can update before the compositor's hit-test tree.
            // Require the real hit target to be ready, not just layout coordinates.
            bool HitHandle() => VisualTreeHelper.FindElementsInHostCoordinates(handle.TransformToVisual(null).TransformPoint(new(22, 26)), shell).Contains(handle);
            await WaitForState(HitHandle, "手柄中心没有实际命中原生控件。手柄纵坐标：" + Grip(2).Y.ToString("F0") + "；可视高度：" + mainScroll!.ActualHeight.ToString("F0"));
            var target = Before(0);
            scheme!["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" };
            require(Press(2), "原生手柄按下未开始。");
            handle.Move?.Invoke(target, 1); shell.UpdateLayout();
            require(nodeDragPreview != null && nodeDropRows[0].Line.Visibility == Visibility.Visible && nodeDropRows[0].Row.Background != null && nodeDropRows[2].Row.Opacity < 1, "缺少拖动整行、落点线或行高亮。");
            var previewTop = Canvas.GetTop(nodeDragPreview!); var shifted = new Point(target.X, target.Y + 14);
            handle.Move?.Invoke(shifted, 1);
            require(Math.Abs(Canvas.GetTop(nodeDragPreview!) - previewTop - 14) < 1, "拖动行没有跟随指针。");
            await Capture(SafePath.Resolve(output, "node-drag-" + theme.ToLowerInvariant() + ".png"));
            require(handle.Release?.Invoke(target, 1) == true && scheme["Candidate"] == null, "释放未重排或未失效已校验配置。");
            require(Names() == "入口 C|入口 A|入口 B" && nodeDragPreview == null, "重排顺序未保存到方案或拖动行残留。");
            await Capture(SafePath.Resolve(output, "node-order-" + theme.ToLowerInvariant() + ".png"));
            var savedCandidate = new JsonObject { ["ValidationStatus"] = "Passed" }; scheme["Candidate"] = savedCandidate;
            handle = nodeDropRows[0].Handle; var click = Grip(0);
            require(Press(0) && handle.Release?.Invoke(click, 1) == false && scheme["Candidate"] == savedCandidate, "点击手柄意外改变顺序或校验状态。");
            require(!Press(0, capture: false) && nodePointerDrag == null, "未取得指针捕获时仍开始拖动。");
            handle = nodeDropRows[2].Handle; var origin = Grip(2); target = Before(0);
            require(Press(2), "取消用例无法开始拖动。");
            handle.Move?.Invoke(target, 2);
            require(nodePointerDrag?.Moved == false && handle.Release?.Invoke(target, 2) == false, "其他指针改变当前拖动。");
            require(!Press(0, 2) && nodePointerDrag?.Source == 2, "第二个指针抢占当前拖动。");
            handle.Move?.Invoke(target, 1); handle.Key?.Invoke(VirtualKey.Escape);
            require(nodePointerDrag == null && nodeDragPreview == null && nodeDropRows.All(row => row.Row.Opacity == 1 && row.Line.Visibility == Visibility.Collapsed) && Names() == "入口 C|入口 A|入口 B" && scheme["Candidate"] == savedCandidate, "Esc 取消未恢复原顺序或清理拖动视觉。");
            require(Press(2), "移出列表用例无法开始。");
            var outside = new Point(-40, target.Y); handle.Move?.Invoke(outside, 1);
            require(handle.Release?.Invoke(outside, 1) == false && Names() == "入口 C|入口 A|入口 B", "列表外释放仍改变顺序。");
            require(Press(2), "失去捕获用例无法开始。"); handle.Move?.Invoke(target, 1); handle.Cancel?.Invoke(1);
            require(nodePointerDrag == null && nodeDragPreview == null && scheme["Candidate"] == savedCandidate, "取消/失去捕获没有清理拖动。");
            handle = nodeDropRows[0].Handle; Navigate("clients");
            require(handle.Press?.Invoke(origin, 1, () => true) == false && nodePointerDrag == null, "旧页面手柄可以修改新页面。");
            nodeDropRows[0].Handle.Key?.Invoke(VirtualKey.Up); nodeDropRows[2].Handle.Key?.Invoke(VirtualKey.Down);
            require(Names() == "入口 C|入口 A|入口 B", "首尾方向键越界。");
            nodeDropRows[0].Handle.Key?.Invoke(VirtualKey.Down);
            require(Names() == "入口 A|入口 C|入口 B", "手柄方向键未调整顺序。");

            for (var index = 4; index <= 20; index++) scheme!["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = "入口 " + index, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry" });
            Navigate("clients"); await Task.Delay(100); mainScroll!.ChangeView(null, 420, null, true);
            await WaitForState(() => Math.Abs(mainScroll.VerticalOffset - 420) < 2 && nodeDropRows.All(row => row.Row.ActualHeight > 0), "长列表没有滚动到测试起点。");
            var visible = nodeDropRows.Select((row, index) => (row, index)).First(item => Grip(item.index).Y > 70 && Grip(item.index).Y < mainScroll.ActualHeight - 70).index;
            handle = nodeDropRows[visible].Handle;
            require(Press(visible), "滚动后的拖动未开始。");
            var edge = new Point(Grip(visible).X, mainScroll.ActualHeight - 12); handle.Move?.Invoke(edge, 1);
            var oldOffset = mainScroll.VerticalOffset;
            await WaitForState(() => mainScroll.VerticalOffset > oldOffset && nodeDragPreview != null, "拖到边缘没有自动滚动。");
            var sourceName = scheme["Nodes"]!.AsArray()[visible]!.Text("name"); var offsetBeforeDrop = mainScroll.VerticalOffset;
            require(handle.Release?.Invoke(edge, 1) == true && scheme["Nodes"]!.AsArray()[visible]!.Text("name") != sourceName, "滚动后的落点不正确。");
            await WaitForState(() => Math.Abs(mainScroll.VerticalOffset - offsetBeforeDrop) < 2 && nodeDragPreview == null, "排序后滚动位置跳变或拖动视觉未清理。");
            scheme["Nodes"]!.AsArray().Clear();
            foreach (var name in new[] { "入口 C", "入口 A", "入口 B" }) scheme["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry" });
            Navigate("clients"); mainScroll.ChangeView(null, 0, null, true);
        }
        finally { CancelNodeReorder(); AppWindow.Resize(originalSize); shell.UpdateLayout(); }
    }
}
