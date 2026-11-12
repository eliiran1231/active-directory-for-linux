using System.Text.Json;
using Ours = AdForLinux.DirectoryServices;

// Clone-only adaptations of the four source-pinned Windows Facts documented in README.
// No directory bindings, PrincipalContexts, or network operations occur here.
if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Run this oracle suite on Linux.");
using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"oracle.json")));
var framework = $"net{Environment.Version.Major}.0-windows";
var oracle = document.RootElement.GetProperty("frameworks").GetProperty(framework);
var count = 0;
var cases = 0;
var current = "";
var occurrences = new Dictionary<int,int>();
void Start(string method) { Finish(); current=method; occurrences.Clear(); cases++; }
void Finish() {
    if(current=="") return;
    foreach(var site in oracle.GetProperty(current).EnumerateObject())
        if(occurrences.GetValueOrDefault(int.Parse(site.Name))!=site.Value.GetProperty("values").GetArrayLength())
            throw new InvalidOperationException($"Unconsumed oracle observations: {current}:{site.Name}");
}
void Check<T>(int line,T actual) {
    var values=oracle.GetProperty(current).GetProperty(line.ToString()).GetProperty("values");
    var index=occurrences.GetValueOrDefault(line);
    if(index>=values.GetArrayLength()) throw new InvalidOperationException("Unexpected observation occurrence");
    var expected=values[index].Deserialize<T>();
    occurrences[line]=index+1; count++;
    if(!EqualityComparer<T>.Default.Equals(expected,actual))
        throw new InvalidOperationException($"{current}:{line} occurrence {index}: Microsoft={expected}; Linux={actual}");
}
void View(Ours.DirectoryVirtualListView view) {
    Check(241,view.BeforeCount); Check(242,view.AfterCount); Check(243,view.Offset);
    Check(244,view.ApproximateTotal); Check(245,view.TargetPercentage);
    Check(247,view.DirectoryVirtualListViewContext is null);
}
// Preserve invalid assignments' control flow; exception identities are not admitted
// by this partial oracle. The subsequent state observations ARE checked.
void Attempt(Action action) { try {action();} catch(ArgumentException) {} }
Start("Directory_searcher_security_mask_validation_matches_microsoft");
using(var ours=new Ours.DirectorySearcher()) {
    for(var value=0;value<=15;value++) {ours.SecurityMasks=(Ours.SecurityMasks)value;Check(142,(int)ours.SecurityMasks);}
    ours.SecurityMasks=(Ours.SecurityMasks)(-1);Check(149,(int)ours.SecurityMasks);
    foreach(var value in new[]{16,int.MaxValue}) {Attempt(()=>ours.SecurityMasks=(Ours.SecurityMasks)value);Check(156,(int)ours.SecurityMasks);}
}
Start("Virtual_list_view_constructors_match_microsoft");
var context=new Ours.DirectoryVirtualListViewContext();
View(new()); View(new(20)); View(new(2,3,10)); View(new(2,3,10,context));
View(new(2,3,"target")); View(new(2,3,"target",context));
Start("Virtual_list_view_validation_and_derived_values_match_microsoft");
Attempt(()=>new Ours.DirectoryVirtualListView(-1));
Attempt(()=>new Ours.DirectoryVirtualListView(-1,0,0));
Attempt(()=>new Ours.DirectoryVirtualListView(0,-1,0));
Attempt(()=>new Ours.DirectoryVirtualListView(0,0,-1));
var view=new Ours.DirectoryVirtualListView();
Attempt(()=>view.ApproximateTotal=-1);Attempt(()=>view.TargetPercentage=-1);Attempt(()=>view.TargetPercentage=101);
view.ApproximateTotal=80;view.TargetPercentage=25;View(view);
view.Offset=40;View(view);view.Target=null!;View(view);
Start("Virtual_list_view_response_update_uses_the_returned_total_for_percentage");
view=new(0,0,500){ApproximateTotal=1000};
view.Update(offset:2,approximateTotal:13,contextId:null);View(view);
Finish();
if(count!=79 || cases!=4) throw new InvalidOperationException("Unexpected coverage count");
var hardcodedCount = HardcodedMirrors.Run();
Console.WriteLine($"PASS: {cases + 12} partial source Facts, {count + hardcodedCount} recorded Microsoft scalar observations ({framework}). No live AD; remaining suite NOT covered.");
