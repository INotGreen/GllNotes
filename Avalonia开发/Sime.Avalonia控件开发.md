







# 

## Installation

```bash
dotnet add package Semi.Avalonia --version 11.0.1
```

Include Semi Design Styles in application:

```xaml
<Application.Styles>
    <StyleInclude Source="avares://Semi.Avalonia/Themes/Index.axaml" />
</Application.Styles>
```

That's all. 

ColorPicker, DataGrid and TreeDataGrid are distributed in separated packages. Please install if you need. 

```bash
dotnet add package Semi.Avalonia.ColorPicker --version 11.0.1
dotnet add package Semi.Avalonia.DataGrid --version 11.0.1
dotnet add package Semi.Avalonia.TreeDataGrid --version 11.0.1
```

```xaml
<Application.Styles>
    <StyleInclude Source="avares://Semi.Avalonia.ColorPicker/Index.axaml" />
    <StyleInclude Source="avares://Semi.Avalonia.DataGrid/Index.axaml" />
    <StyleInclude Source="avares://Semi.Avalonia.TreeDataGrid/Index.axaml" />
</Application.Styles>
```

## 





# 控件UI

## 1.Border

`Border` 是一个布局和装饰控件，它为其包含的子元素提供边框、背景和可能的间距（margin 和 padding）。`Border` 控件常用于改善用户界面的视觉效果，为元素添加可视边界，并提供一种简单的方式来创建带有背景色和圆角的区域。

1. **Background**: 设置 `Border` 的背景颜色。
2. **BorderBrush**: 设置边框的颜色。
3. **BorderThickness**: 设置边框的粗细。可以分别指定左、上、右、下四个方向的边框粗细。
4. **CornerRadius**: 设置边框的圆角半径。通过这个属性，你可以创建圆角矩形的边框效果。
5. **Padding 和 Margin**: `Padding` 指的是边框与其内部子元素之间的空间，而 `Margin` 指的是边框与其外部元素之间的空间。
6. **Child**: `Border` 可以包含一个子元素，例如文本、图像或其他控件。

例如

```xml
<Border
    BorderBrush="Blue"
    BorderThickness="2"
    Background="Yellow"
    CornerRadius="10">
    <!-- 在这里放置子元素 -->
</Border>
```

## 2.Window 定义:

- `xmlns` 和 `x`: 这些是XML命名空间，用于定义元素和属性。
- `mc:Ignorable`, `d:DesignWidth`, `d:DesignHeight`: 用于设计时支持，例如在可视化设计器中。
- `x:Class`: 指定与此XAML文件关联的后端C#类。
- `x:DataType`: 指定这个窗口的数据上下文类型，通常用于绑定到ViewModel。
- `Icon`, `Title`: 设置窗口的图标和标题。

## 3.DockPanel:

- `LastChildFill="True"`: 最后一个子元素填充剩余空间。
- `DockPanel` 使用了嵌套的方式，其中包含两个主要的界面元素。

## 4.button:

- 第一个内部 `DockPanel` 包含两个按钮。
- `Button DockPanel.Dock="Left"`: 一个按钮靠左对齐，绑定到 `OpenFileCommand`。
- `Button DockPanel.Dock="Right"`: 另一个按钮靠右对齐，绑定到 `SaveFileCommand`。
- 这些按钮用于打开和保存文件，操作通过绑定到ViewModel中的命令实现。

## 5.ListBox:

- `ListBox`: 显示绑定到 `ErrorMessages` 的数据。
- 这可能用于显示文件操作过程中的错误消息。

## 6.TextBox:

- 用于显示和编辑文件内容。
- `Text="{Binding FileText, Mode=TwoWay}"`: 将TextBox的文本内容绑定到ViewModel的 `FileText` 属性。`TwoWay` 模式意味着更改会在ViewModel和UI之间双向同步。
- `AcceptsReturn`, `AcceptsTab`: 允许在TextBox内使用回车键和Tab键。